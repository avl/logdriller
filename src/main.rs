extern crate core;

use crate::lines::{AnalyzedLogLines, AnalyzedRow, ColumnDefinition, FastLogLines, FastLogLinesTrait, LogLineId, MemMappedFile};
use crate::string_carrier::StringCarrier;
use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use indexmap::{IndexMap, map::Entry};
use itertools::Itertools;
use memchr::memchr;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use ratatui::crossterm::event::KeyModifiers;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    layout::{Flex, Size},
    palette::{Hsl, RgbHue, encoding::Srgb, rgb::Rgb},
    prelude::{Color, Constraint, Direction, Layout, Line, Rect, Style, Stylize},
    style::Styled,
    text::Span,
    widgets::{Block, Borders, Clear, Paragraph, Row, Table, TableState},
};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use savefile::{
    Deserialize, Deserializer, LittleEndian, Serialize, Serializer,
    prelude::{ReadBytesExt, Savefile},
};
use std::borrow::Cow;
use std::collections::HashSet;
use std::ops::{Add, Range};
use std::panic::AssertUnwindSafe;
use std::sync::mpsc::SyncSender;
use std::{
    collections::{BinaryHeap, HashMap, VecDeque},
    ffi::OsString,
    fmt::{Debug, Display, Formatter},
    fs::File,
    io::{BufRead, BufReader, BufWriter, Cursor, Read, Write},
    net::{TcpListener, TcpStream},
    panic::catch_unwind,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use std::marker::PhantomData;
use std::path::Path;
use tui_textarea::TextArea;

mod line_parser;
mod trie;

use crate::trie::{Trie, TrieKey};

const AFTER_HELP: &str = "
Examples:
    logdriller path/to/some/executable
    logdriller -- path/to/some/executable --parameter-to-executable=1
";

#[derive(Debug, Parser)]
#[command(version, about, long_about = None, after_help = AFTER_HELP)]
struct LogdrillerArgs {
    /// Path to source of application that is being run
    #[arg(short = 's', long)]
    source: Option<String>,

    #[arg(long, hide = true)]
    debug_notify: bool,

    #[arg(long, hide = true)]
    debug_capturer: bool,

    #[arg(long, hide = true)]
    daemon: bool,

    /// Show the given file, instead of running an application
    #[arg(long, short = 'f')]
    file: Option<PathBuf>,

    /// Application to run, with arguments
    values: Vec<String>,

    /// Maximum number of lines to capture
    #[arg(short = 'n', long)]
    max_lines: Option<usize>,
}

pub trait ReadSavefileExt: Read {
    fn read_msg<T: Deserialize>(&mut self) -> Result<T> {
        let size = self.read_u32::<LittleEndian>()?;
        let mut buf = vec![0; size as usize];
        self.read_exact(&mut buf[..])?;
        let t = Deserializer::bare_deserialize(&mut Cursor::new(buf), 0)?;
        Ok(t)
    }
}

pub trait WriteSavefileExt: Write {
    fn write_msg<T: Serialize>(&mut self, obj: &T) -> Result<()> {
        let mut buf = Vec::new();
        Serializer::bare_serialize(&mut buf, 0, obj)?;
        use byteorder::WriteBytesExt;
        self.write_u32::<LittleEndian>(buf.len() as u32)?;
        self.write_all(&buf)?;
        Ok(())
    }
}
impl<T> ReadSavefileExt for T where T: Read {}
impl<T> WriteSavefileExt for T where T: Write {}

fn defstyle() -> Style {
    Style::new()
        .bg(Color::Rgb(192, 192, 192))
        .fg(Color::Rgb(0, 0, 0))
}
fn parse_delta(prev: &str, now: &str, path: &Arc<PathBuf>, tx: &Buffer, debug_notify: bool) {
    let mut prev_lines = HashMap::<&str, usize>::new();
    for line in prev.lines() {
        *prev_lines.entry(line).or_default() += 1;
    }
    for (line_number, line) in now.lines().enumerate() {
        let line_number = line_number + 1; //Editors count 1 as first line
        if let Some(x) = prev_lines.get_mut(line)
            && *x >= 1
        {
            *x -= 1;
            continue;
        }
        let mut finger = Vec::new();

        fingerprint(line, &mut finger);

        if !finger.is_empty() {
            let tp = TracePoint {
                file: path.clone(),
                line_number,
                tracepoint: u32::MAX,
                color_index: ColorIndex(0),
            };
            if debug_notify {
                println!("New tracepoint: {:?}", finger);
            }
            let tp = TracePointData {
                fingerprint: Fingerprint(finger),
                tp,
                active: line.trim_end().ends_with("//"),
                capture: false,
                negative: false,
                matches: AtomicUsize::new(0),
            };
            tx.push(tp);
        }
    }
}

fn fingerprint(line: &str, fingerprint: &mut Vec<TrieKey>) -> Option<()> {
    let mut tokens = line.chars().peekable();
    let mut wild = true;
    loop {
        let tok = tokens.next()?;
        if tok == '"' {
            let mut depth = 0i32;
            loop {
                let tok = tokens.next()?;
                if tok == '\\' {
                    _ = tokens.next()?;
                    continue;
                }
                if tok == '"' {
                    break;
                } else if tok == '{' {
                    wild = true;
                    depth += 1;
                } else if tok == '}' {
                    depth -= 1;
                } else if depth == 0 {
                    let mut buf = [0; 4];
                    let bytes = tok.encode_utf8(&mut buf).as_bytes();
                    for byt in bytes {
                        if wild {
                            fingerprint.push(TrieKey::WildcardThen(*byt));
                        } else {
                            fingerprint.push(TrieKey::Exact(*byt));
                        }
                        wild = false;
                    }
                }
            }
        }
    }
}

#[derive(Savefile, Default, Clone, Debug)]
struct MatchSequence {
    range: Vec<(u32, u32)>,
}

impl MatchSequence {
    pub fn clear(&mut self) {
        self.range.clear();
    }
    #[allow(unused)]
    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }
    #[allow(unused)]
    pub(crate) fn visit(&self, len: usize, mut visitor: impl FnMut(usize, usize, bool)) {
        let mut expected_start = 0;
        for (start, end) in &self.range {
            if *start as usize != expected_start {
                visitor(expected_start, *start as usize, false);
            }
            visitor(*start as usize, *end as usize, true);
            expected_start = *end as usize;
        }
        if expected_start != len {
            visitor(expected_start, len, false);
        }
    }
}

struct Restore {
    range_count: u32,
    end_at: u32,
}
impl MatchSequence {
    pub fn add(&mut self, index: u32) {
        if let Some(last) = self.range.last_mut()
            && index == 0
        {
            last.1 += 1;
            return;
        }
        if let Some(last) = self.range.last().map(|x| x.1) {
            self.range.push((last + index, last + index + 1));
        } else {
            self.range.push((index, index + 1));
        }
    }
    pub fn save(&mut self) -> Restore {
        Restore {
            range_count: self.range.len() as u32,
            end_at: self.range.last().map(|x| x.1).unwrap_or(0),
        }
    }
    pub fn restore(&mut self, restore: Restore) {
        self.range.truncate(restore.range_count as usize);
        if let Some(last) = self.range.last_mut() {
            last.1 = restore.end_at;
        }
    }
}

fn check_matching<'a>(
    fingerprint_trie: &mut Trie<TracePoint>,
    trace_point_data: &[TracePointData],
    row: &AnalyzedRow<'a>,
) -> bool {
    if fingerprint_trie.empty_trie() {
        return true;
    }
    let mut any_positive_hit = false;
    let mut any_negative_hit = false;

    let len = trace_point_data.len();
    for item in row.cols() {
        fingerprint_trie.search_fn_fast(
            item,
            |hit| {
                let tp: &TracePointData = &trace_point_data[hit.tracepoint as usize];
                tp.matches.fetch_add(1, Ordering::Relaxed);
                if tp.active {
                    if tp.negative {
                        any_negative_hit = true;
                    } else {
                        any_positive_hit = true;
                    }
                }
            },
            len,
        );
    }
    any_positive_hit && !any_negative_hit
}



/// Check if 'line' matches the filter, and adds it to the `matching_lines`
fn add_if_matching<'a>(
    fingerprint_trie: &mut Trie<TracePoint>,
    matching_lines: &mut VecDeque<LogLineId>,
    trace_point_data: &mut [TracePointData],
    row: &AnalyzedRow<'a>,
) {
    let id = row.id();
    if check_matching(fingerprint_trie, trace_point_data, row) {
        matching_lines.push_back(id);
    }
}

/// Return all matches of the expressions in Trie to the 'line'
fn get_matches(fingerprint_trie: &mut Trie<TracePoint>, line: &str) -> Vec<TpMatch> {
    let mut tps = Vec::new();
    fingerprint_trie.search_fn(line, |hit, m| {
        tps.push((hit.tracepoint, m.clone(), hit.color_index));
        true
    });

    if !tps.is_empty() {
        tps.into_iter()
            .map(|(tp, matchseq, color_index)| TpMatch { tp, hits: matchseq, color_index})
            .collect()
    } else {
        Vec::new()
    }
}


impl<T:FastLogLinesTrait> State<T> {
    pub(crate) fn apply_parsing_config(&mut self, config: ParsingConfiguration) {
        self.state_config.config = config;
        self.reapply_parsing_config();
    }
    pub(crate) fn reapply_parsing_config(&mut self) {
        let coldef = if !self.state_config.raw {
            ColumnDefinition {
                analyzer: self.state_config.config.make_analyzer(),
                col_names: self.state_config.config.fields.iter().map(|x| x.to_string()).collect(),
            }
        } else {
            ColumnDefinition {
                col_names: vec!["".to_string()],
                analyzer: Box::new(|line, out| {
                    out.push(0..line.len() as u32);
                }),
            }
        };

        self.all_lines.update(coldef);
    }
    pub(crate) fn get_available_fields(&self) -> Vec<LogField> {
        let mut fields: HashSet<LogField> = [LogField::Raw].into_iter().collect();
        for (_line_id, line) in self.all_lines.loglines.iter() {
            simple_json::parse_all(line, |_, range| {
                fields.insert(LogField::parse(
                    &line[range.start as usize..range.end as usize],
                ));
            });
        }
        let mut fields: Vec<_> = fields.into_iter().collect();
        fields.sort();
        fields
    }
    fn parsing_enabled_configuration(&self) -> ParsingConfigState {
        let mut choosable_fields = self
            .state_config.config
            .fields
            .iter()
            .map(|f| (true, f.clone()))
            .collect::<Vec<_>>();

        for field in self.get_available_fields() {
            if !choosable_fields.iter().any(|x| x.1 == field) {
                choosable_fields.push((false, field.clone()));
            }
        }
        ParsingConfigState::Enabled(choosable_fields, TableState::new())
    }
    fn get_parsing_configuration(&self) -> ParsingConfigState {
        self.parsing_enabled_configuration()
    }

    fn add_tracepoint_trie(trie: &mut Trie<TracePoint>, tp: &TracePointData) {
        trie.push(&tp.fingerprint.0, tp.tp.clone());
    }
    fn rebuild_trie(&mut self) {
        self.fingerprint_trie = Trie::new();
        self.capture_fingerprint_trie = Trie::new();
        for (i, tp) in self.state_config.tracepoints.iter_mut().enumerate() {
            tp.tp.tracepoint = i as u32;
            {
                Self::add_tracepoint_trie(&mut self.fingerprint_trie, tp);
                if tp.capture {
                    Self::add_tracepoint_trie(&mut self.capture_fingerprint_trie, tp);
                }
            }
        }

        self.rebuild_matches()
    }
    fn rebuild_matches(&mut self) {
        self.generation += 1;

        self.matching_lines.clear();
        for tp in &mut self.state_config.tracepoints {
            tp.matches = AtomicUsize::new(0);
        }

        let rows = self.all_lines.iter().collect::<Vec<_>>();

        let mut matching_lines: Vec<LogLineId> = rows
            .into_par_iter()
            .map_init(
                || self.fingerprint_trie.clone(),
                |trie, row| {
                    let id = row.id();
                    if check_matching(trie, &self.state_config.tracepoints[..], &row) {
                        id
                    } else {
                        LogLineId::MAX
                    }
                },
            )
            .filter(|x| *x != LogLineId::MAX)
            .collect();
        matching_lines.sort();
        self.matching_lines = matching_lines.into();

        /*        for row in self.all_lines.par_iter() {
            // Also, add a "recent fingerprints" section in ratatui
            State::add_if_matching(
                &mut self.fingerprint_trie,
                &mut self.matching_lines,
                &mut self.tracepoints[..],
                row,
            );
        }*/
    }
}

impl<T:FastLogLinesTrait> State<T> {
    fn calculate_free_color_index(&self) -> ColorIndex {
        let mut free = 0;
        let mut used_colors = self.state_config.tracepoints.iter().map(|x|x.tp.color_index).collect::<Vec<_>>();
        used_colors.sort();
        for used_color in used_colors {
            if used_color.0 != free {
                return ColorIndex(free);
            }
            free = used_color.0 + 1;
        }
        return ColorIndex(free);
    }
    fn add_tracepoint(&mut self,
                      edited: Option<&Fingerprint>,
                      mut tp: TracePointData) {
        let any_active = self.state_config.tracepoints.iter().any(|x| x.active);
        if edited.is_none() {
            tp.tp.color_index = self.calculate_free_color_index();
        }
        if let Some(edited) = edited &&
            let Some(edited_tp) = self.state_config.tracepoints.iter_mut().find(|x|&x.fingerprint == edited) {
            *edited_tp = tp;
        }
        else if let Some(prev_tp) = self
            .state_config.tracepoints
            .iter_mut()
            .find(|x| x.fingerprint == tp.fingerprint && x.tp.file == tp.tp.file)
        {
            if prev_tp.active && tp.active {
                return;
            }
            if !prev_tp.active && !tp.active {
                return;
            }
            prev_tp.active = tp.active;
            drop(tp);
        } else {
            let mut indices: Vec<_> = self.state_config.tracepoints.iter().map(|x| x.tp.tracepoint).collect();
            indices.sort();
            let tp_index = if let Some(_hole) = indices.windows(2).find(|xs| xs[1] != xs[0] + 1) {
                panic!("Holes shouldn't exist");
            } else {
                indices.len() as u32
            };

            tp.tp.tracepoint = tp_index;
            self.state_config.tracepoints.push(tp);
        }
        if !any_active && !self.state_config.do_filter {
            self.state_config.do_filter = true;
        }
        self.rebuild_trie();
        self.rebuild_matches();
    }

    fn capture_sel(&self) -> Option<LogLineId> {
        let was_sel: Option<LogLineId> = self.selected_output.and_then(|index: usize| {
            if self.state_config.do_filter {
                self.matching_lines.get(index).copied()
            } else {
                Some(self.all_lines.get(index)?.id())
            }
        });
        was_sel
    }

    fn restore_sel(
        &mut self,
        was_sel: Option<LogLineId>,
        output_table_state: &mut TableState,
        do_center: &mut bool,
    ) {
        if let Some(sel) = was_sel {
            let newsel = if self.state_config.do_filter {
                self.matching_lines.iter().position(|x| sel == *x)
            } else {
                self.all_lines.position_of(sel)
            };
            self.selected_output = newsel;
            output_table_state.select(newsel);
            *do_center = true;
        }
    }

    fn focus_current_tracepoint(&mut self, back: bool) -> Option<usize> {
        if let Some(filter) = self.state_config.selected_filter && filter < self.state_config.tracepoints.len(){
            if self.matching_lines.is_empty() {
                return None;
            }
            let start = self.selected_output.unwrap_or(if back {
                0
            } else {
                self.matching_lines.len().saturating_sub(1)
            });
            let start = start.min(self.matching_lines.len() - 1);

            let mut trie = Trie::new();
            Self::add_tracepoint_trie(&mut trie, &self.state_config.tracepoints[filter]);
            let mut visited_count = 0;
            let total_count = self.matching_lines.len();
            let mut cur = start;
            let mut next = || {
                if visited_count == total_count {
                    return None;
                }
                visited_count += 1;
                if back {
                    cur = cur.checked_sub(1).unwrap_or(total_count.saturating_sub(1));
                } else {
                    cur += 1;
                    if cur >= total_count {
                        cur = 0;
                    }
                }
                Some(cur)
            };

            while let Some(i) = next() {
                let message_id = &self.matching_lines[i];
                let message = self.all_lines.get_by_id(*message_id);
                let have_hit = message.cols().any(|col| {
                    let mut have_hit = false;
                    trie.search_fn_fast(
                        col,
                        |hit| {
                            have_hit = true;
                        },
                        1,
                    );
                    have_hit
                });
                if have_hit {
                    debug_assert!(i < 1<<50);
                    self.selected_output = Some(i);
                    return Some(i);
                }
            }
        }
        None
    }

    fn save(&self) {
        let mut f = BufWriter::new(File::create(LOGDRILLER_FILE).unwrap());
        Serializer::save(&mut f, SAVEFILE_VERSION, &self.state_config, false).unwrap();
        f.flush().unwrap();
    }
}

fn do_add_line<T: FastLogLinesTrait>(
    state: &mut State<T>,
    line: Option<&str>
) -> bool {
    let mut ignored = false;
    if !state.all_lines.push(line, |analyzed| {
        if !check_matching(
            &mut state.capture_fingerprint_trie,
            &mut state.state_config.tracepoints,
            &analyzed,
        ) {
            ignored = true;
            return false;
        }
        true
    }) {
        return false;
    }
    if ignored {
        return true;
    }

    let last = state.all_lines.last();

    add_if_matching(
        &mut state.fingerprint_trie,
        &mut state.matching_lines,
        &mut state.state_config.tracepoints,
        &last,
    );
    drop(last);

    if state.all_lines.len() > state.max_lines && T::SUPPORT_POP{
        let next_front_id = state.all_lines.loglines.first_id() + 1;
        if let Some(front) = state.matching_lines.front()
            && *front <= next_front_id
        {
            let front = state.matching_lines.pop_front().unwrap();
            let front = state.all_lines.get_by_id(front);
            for col in front.cols() {
                for m in get_matches(&mut state.fingerprint_trie, col) {
                    state.state_config.tracepoints[m.tp as usize]
                        .matches
                        .fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
        state.all_lines.pop_front();
    }
    state.generation += 1;
    true
}

fn mainloop<T: FastLogLinesTrait>(
    state: &mut State<T>,
    program_lines: &mut mpsc::Receiver<DiverEvent>,
    string_senders: &mut [SyncSender<StringCarrier>; 2],
) -> Result<bool /*any change (even if just a new total line counter value)*/> {

    let start = Instant::now();
    const SLICE_MS: u64 = 50;
    let mut change = false;
    if !T::SUPPORT_ADD {
        let mut any_added = false;
        let mut counter = 0;
        loop {
            let added = do_add_line(state, None);
            if !added {
                break;
            }
            if counter > 100 {
                counter = 0;
                if start.elapsed().as_millis() > SLICE_MS as u128 {
                    break;
                }
            }
            counter += 1;
            change = true;
        }
    }


    let mut time_remaining = SLICE_MS;
    let mut counter = 0;
    loop {
        counter += 1;
        if counter > 100 {
            time_remaining = SLICE_MS.saturating_sub(start.elapsed().as_millis() as u64);
            if time_remaining == 0 {
                return Ok(change);
            }
        }
        let event = match program_lines.try_recv() {
            Ok(event) => event,
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                time_remaining = SLICE_MS.saturating_sub(start.elapsed().as_millis() as u64);
                return Ok(change);
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                bail!("disconnected");
            }
        };
        change = true;

        match event {
            DiverEvent::SourceChanged(tp) => {
                state.add_tracepoint(None, tp);
                state.save();
            }
            DiverEvent::ProgramOutput(mut lines, channel) => {
                for line in lines.all() {


                    state.total += 1;
                    if state.pause {
                        state.generation += 1;
                        continue;
                    }

                    do_add_line(state, Some(&*line));
                }
                lines.clear();
                string_senders[channel].send(lines)?;
            }
        }
    }
}

#[derive(Default)]
struct ReadManyLines {
    scratch: Vec<u8>,
}

impl ReadManyLines {
    fn append(candidate: &[u8], f: &mut impl FnMut(&str) -> Result<()>) -> Result<()> {
        match String::from_utf8_lossy(candidate) {
            Cow::Borrowed(x) => {
                f(x)?;
            }
            Cow::Owned(o) => {
                f(&o)?;
            }
        }
        Ok(())
    }
    fn read_many_lines<T: Read>(
        &mut self,
        read: &mut BufReader<T>,
        mut f: impl FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        let mut buf = read.fill_buf()?;
        let mut l = 0;
        let mut limit = 0;
        while let Some(index) = memchr(b'\n', buf) {
            if !self.scratch.is_empty() {
                self.scratch.extend(&buf[..index]);
                Self::append(&self.scratch, &mut f)?;
                self.scratch.clear();
            } else {
                Self::append(&buf[..index], &mut f)?;
            }
            buf = &buf[index + 1..];
            l += index + 1;
            limit += 1;
            if limit > 200 {
                read.consume(l);
                return Ok(());
            }
        }
        if !buf.is_empty() {
            l += buf.len();
            self.scratch.extend(buf);
        }
        read.consume(l);

        Ok(())
    }
}
const STRING_DEFAULT_CAP: usize = 200;

const STRINGS_PER_MAGAZINE: usize = 4096;
const STRING_CARRIER_COUNT: usize = 100;
mod string_carrier {
    use crate::{STRING_DEFAULT_CAP, STRINGS_PER_MAGAZINE};

    pub struct StringCarrier {
        strings: Vec<String>,
        count: usize,
    }

    impl Default for StringCarrier {
        fn default() -> Self {
            StringCarrier {
                strings: vec![String::with_capacity(STRING_DEFAULT_CAP); STRINGS_PER_MAGAZINE],
                count: 0,
            }
        }
    }
    impl StringCarrier {
        pub(crate) fn clear(&mut self) {
            self.count = 0;
        }
        pub(crate) fn any(&self) -> bool {
            self.count != 0
        }
        pub fn full(&self) -> bool {
            self.count == self.strings.len()
        }
        pub fn all(&self) -> &[String] {
            &self.strings[0..self.count]
        }
        pub fn push(&mut self, string: &str) -> Result<(), ()> {
            if self.count == self.strings.len() {
                return Err(());
            }
            let s = &mut self.strings[self.count];
            s.clear();
            s.push_str(string);
            self.count += 1;
            Ok(())
        }
    }
}

fn capturer(
    child_out: impl Read,
    program_lines: mpsc::SyncSender<DiverEvent>,
    string_receiver: mpsc::Receiver<StringCarrier>,
    channel: usize,
    debug_capturer: bool,
) -> Result<()> {
    let mut child_out = BufReader::with_capacity(1_000_000, child_out);

    let mut line_buf = ReadManyLines::default();
    let mut string_magazine = None;
    loop {
        //let mut count = 0;
        line_buf.read_many_lines(&mut child_out, |raw_line| {
            {
                if debug_capturer {
                    println!("Captured: {}", raw_line);
                }
                let line: &str;
                let temp;
                if memchr(b'\x1b', raw_line.as_bytes()).is_none() {
                    line = raw_line;
                } else {
                    temp = strip_ansi_codes(raw_line);
                    line = &temp;
                };
                /*count += 1;
                let line = format!("{}:{}",line, count);*/

                // If no message was extracted from JSON, use the entire line as the message
                /*if message.is_empty() {

                    // At some point we may figure out how to correctly parse "pretty" tracing
                    // output and/or "full" tracing output (i.e, non json based):
                    /*if let Some(line) = parse_log_line(&line) {
                        timestamp = line.time;
                        target = line.namespace;
                        level = line.level;
                        message = line.message;
                        fields = line.meta;
                    } else {*/

                    timestamp = "".to_string();
                    target = "".to_string();
                    level = "".to_string();
                    message = line.to_string();
                    fields = "".to_string();

                    //}
                }*/

                if debug_capturer {
                    return Ok(());
                }

                if string_magazine
                    .as_ref()
                    .map(|x: &StringCarrier| x.full())
                    .unwrap_or(true)
                {
                    if let Some(full_magazine) = string_magazine.take() {
                        program_lines
                            .send(DiverEvent::ProgramOutput(full_magazine, channel))
                            .unwrap();
                    }
                    string_magazine = Some(string_receiver.recv()?);
                }
                let string_magazine: &mut StringCarrier = string_magazine.as_mut().unwrap();
                string_magazine.push(line).expect("magazine has capacity");
                /*loglines.append(
                    string_to_reuse
                                      /*LogLine {
                                          time: timestamp,
                                          target,
                                          level,
                                          message,
                                          fields,
                                      }*/
                );*/
                Ok(())
            }
        })?;

        if let Some(magazine) = string_magazine.as_ref()
            && magazine.any()
        {
            program_lines
                .send(DiverEvent::ProgramOutput(
                    string_magazine.take().unwrap(),
                    channel,
                ))
                .unwrap();
        }
    }
}

#[derive(Savefile, Debug, Clone)]
struct TracePoint {
    file: Arc<PathBuf>,
    line_number: usize,
    tracepoint: u32,
    #[savefile_versions="1.."]
    color_index: ColorIndex
}

pub enum DiverEvent {
    SourceChanged(TracePointData),
    ProgramOutput(StringCarrier, usize /*channel 0 or 1*/),
}

#[derive(Savefile, Clone, PartialEq)]
pub struct Fingerprint(Vec<TrieKey>);

impl Debug for Fingerprint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fingerprint({})", self)
    }
}
impl Fingerprint {
    pub fn parse(s: &str) -> Fingerprint {
        let mut t = Vec::new();
        let mut wild = true;

        for c in s.as_bytes() {
            if *c == b'*' {
                wild = true;
                continue;
            }
            if wild {
                wild = false;
                t.push(TrieKey::WildcardThen(*c));
            } else {
                t.push(TrieKey::Exact(*c));
            }
        }
        if t.is_empty() && s.contains('*') {
            t.push(TrieKey::Any);
        }

        Fingerprint(t)
    }
}

impl Display for Fingerprint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut output = Vec::new();
        for key in self.0.iter() {
            match *key {
                TrieKey::Eof => {
                    output.push(b'$');
                }
                TrieKey::Exact(b) => {
                    output.push(b);
                }
                TrieKey::WildcardThen(b) => {
                    output.push(b'*');
                    output.push(b);
                }
                TrieKey::Any => {
                    output.push(b'*');
                }
            }
        }
        if output.len() > 1 && output.starts_with("*".as_bytes()) {
            output.remove(0);
        }
        let output = String::from_utf8(output).unwrap();
        write!(f, "{output}")
    }
}

#[derive(Savefile, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
struct ColorIndex(usize);

#[derive(Savefile, Debug)]
pub struct TracePointData {
    fingerprint: Fingerprint,
    tp: TracePoint,
    active: bool,
    capture: bool,
    negative: bool,
    matches: AtomicUsize,
}
impl Clone for TracePointData {
    fn clone(&self) -> Self {
        TracePointData {
            fingerprint: self.fingerprint.clone(),
            tp: self.tp.clone(),
            active: self.active,
            capture: self.capture,
            negative: self.negative,
            matches: AtomicUsize::new(self.matches.load(Ordering::Relaxed)),

        }
    }
}

pub mod lines {
    use itertools::Itertools;
use std::collections::VecDeque;
    use std::fs::File;
    use std::io::SeekFrom;
    use std::ops::{Add, Index, Range};
    use std::path::Path;
    use std::str::from_utf8_unchecked;
    use memchr::memchr;
    use memmap2::Mmap;
    use ratatui::DefaultTerminal;

    pub fn to_usize(range: Range<u32>) -> Range<usize> {
        range.start as usize..range.end as usize
    }

    pub trait FastLogLinesTrait{
        const SUPPORT_ADD: bool;
        const SUPPORT_POP: bool;
        fn preview<'a>(&'a mut self, msg: Option<&'a str>) -> Option<(&'a str, LogLineId)>;
        fn len(&self) -> usize;
        fn first_id(&self) -> LogLineId;
        fn get(&self, line_id: LogLineId) -> Option<&str>;
        fn push(&mut self, msg: &str);
        fn pop(&mut self);
        fn iter(&self) -> impl Iterator<Item=(LogLineId, &str)>;
        fn iter_values(&self) -> impl Iterator<Item=&str>;
        fn index_impl(&self, index: usize) -> Option<&str>;
        fn start_id(&self) -> usize;
        
        fn maybe_grow(&mut self) -> Option<&str>;
    }


    pub struct MemMappedFile {
        mmap: Mmap,
        offsets: Vec<usize>,
        last_parsed: usize,
        datalen: usize,
    }

    impl MemMappedFile {
        pub fn new(path: &Path) -> anyhow::Result<Self> {
            use std::io::Seek;
            // SAFETY:
            // Basically, we punt to the user that things might crash if the file is modified
            // This is just a log analysis tool, such crashes are assumed ok
            let mut file = File::open(path)?;
            file.seek(SeekFrom::End(0))?;
            let datalen = file.stream_position()? as usize;
            file.seek(SeekFrom::Start(0))?;

            Ok(Self {
                mmap: unsafe { Mmap::map(&file)? },
                offsets: vec![],
                datalen,
                last_parsed: 0,
            })
        }
        fn index_impl_verify(&self, index: usize, verify: bool) -> Option<&str> {
            let start = self.offsets[index];
            let end = self
                .offsets
                .get(index + 1)
                .map(|x| x)?;

            // We take care to ensure slices are always contiguous
            let raw_bytes = &self.mmap[start..*end];

            if verify {
                str::from_utf8(raw_bytes).unwrap();
            }

            {
                Some(unsafe { str::from_utf8_unchecked(raw_bytes) })
            }
        }

    }


    impl FastLogLinesTrait for MemMappedFile {
        const SUPPORT_ADD: bool = false;

        fn maybe_grow(&mut self) -> Option<&str> {
            if self.last_parsed < self.datalen {
                if let Some(index) = memchr(b'\n', &self.mmap[self.last_parsed..self.datalen]) {
                    self.offsets.push(self.last_parsed);
                    self.last_parsed = (self.last_parsed + index+1).min(self.datalen);
                } else {
                    self.offsets.push(self.last_parsed);
                    self.last_parsed = self.datalen;
                }

                Some(self.index_impl_verify(self.offsets.len()-1, true).unwrap())
            } else {
                None
            }
        }
        fn preview<'a>(&'a mut self, _msg: Option<&'a str>) -> Option<(&'a str, LogLineId)> {
            let next_id = self.offsets.len();
            let s = self.maybe_grow()?;
            Some((s, LogLineId(next_id)))
        }

        fn len(&self) -> usize {
            self.offsets.len()
        }

        fn first_id(&self) -> LogLineId {
            LogLineId(0)
        }

        fn get(&self, line_id: LogLineId) -> Option<&str> {
            self.index_impl(line_id.0)
        }

        fn push(&mut self, msg: &str) {
            unimplemented!()
        }

        fn pop(&mut self) {
        }

        fn iter(&self) -> impl Iterator<Item=(LogLineId, &str)> {
            self.iter_values().enumerate().map(|(idx,val)|
                (LogLineId(idx), val))
        }

        fn iter_values(&self) -> impl Iterator<Item=&str> {

            self.offsets.iter().copied().chain(std::iter::once(self.last_parsed)).tuple_windows()
                .map(|(a,b)|{

                    let raw_bytes = &self.mmap[a..b];
                    #[cfg(debug_assertions)]
                    {
                        str::from_utf8(raw_bytes).unwrap()
                    }
                    #[cfg(not(debug_assertions))]
                    {
                        unsafe { str::from_utf8_unchecked(raw_bytes) }
                    }
                })
        }

        fn index_impl(&self, index: usize) -> Option<&str> {
            self.index_impl_verify(index, false)
        }

        fn start_id(&self) -> usize {
            0
        }

        const SUPPORT_POP: bool = false;
    }

    #[derive(Default)]
    pub struct FastLogLines {
        /// Offset of each current line. The offset is a byte-offset from
        /// the start of the infinite stream.
        offsets: VecDeque<usize>,
        /// Offset of first current line in 'raw_data'
        start_offset: usize,
        start_id: usize,
        /// Bytes of the stream. Only contains those bytes actually used.
        /// offsets[0] - start_offset = index into this collection
        raw_data: VecDeque<u8>,
    }
    fn truncate(s: &str, max_bytes: usize) -> &str {
        if s.len() <= max_bytes {
            return s;
        }

        let mut prev_index = 0;
        let it = s.char_indices();

        for (i, _) in it {
            // start index of previous iteration must be an allowed end index,
            // since it must be <= max_bytes or we would have break:ed out of the loop
            if i > max_bytes {
                break;
            }
            prev_index = i;
        }
        debug_assert!(prev_index < s.len());
        &s[0..prev_index]
    }

    fn last_slice<T>(v: &VecDeque<T>) -> &[T] {
        let (a, b) = v.as_slices();
        if b.is_empty() { a } else { b }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
    // Numerical id for this row. Each successive row is numbered one higher
    pub struct LogLineId(usize);
    impl LogLineId {
        pub const MAX: LogLineId = LogLineId(usize::MAX);
    }
    impl Add<usize> for LogLineId {
        type Output = LogLineId;

        fn add(self, rhs: usize) -> Self::Output {
            LogLineId(self.0 + rhs)
        }
    }

    impl FastLogLines {
        const MAX_LINE_LENGTH: usize = 1_000_000;
        pub fn len(&self) -> usize {
            self.offsets.len()
        }

    /// Returns start-index of inserted 'msg'.
    /// This is the only method that modifies the collection, and it ensures
    /// all added strings are always contiguous
    fn push_contiguous(&mut self, msg: &str) -> usize {
        for _ in 0..100 {
            if self.raw_data.len() + msg.len() < self.raw_data.capacity() {
                self.raw_data.reserve(msg.len());
                // Make sure everything is contiguous after every reallocation
                self.raw_data.make_contiguous();
            }
            // This will never reallocate
            self.raw_data.extend(msg.as_bytes());
            if last_slice(&self.raw_data).len() >= msg.len() {
                // The newly inserted element is fully in the last slice - it is contiguous
                return self.raw_data.len() - msg.len();
            }
        }
        panic!(
            "unexpected error - element inserted into VecDeque was consistently non-contiguous"
        )
    }
}

impl FastLogLinesTrait for FastLogLines {

    fn len(&self) -> usize {
        self.offsets.len()
    }

    fn index_impl(&self, index: usize) -> Option<&str> {

        if index >= self.offsets.len() {
            return None;
        }
        let start = self.offsets[index] - self.start_offset;
        let end = self
            .offsets
            .get(index + 1)
            .map(|x| x - self.start_offset)
            .unwrap_or(self.raw_data.len());
        // We take care to ensure slices are always contiguous
        let raw_bytes = self.raw_data.get_range(start..end);
        #[cfg(debug_assertions)]
        {
            Some(str::from_utf8(raw_bytes).unwrap())
        }
        #[cfg(not(debug_assertions))]
        {
            Some(unsafe { str::from_utf8_unchecked(raw_bytes) })
        }

    }

    fn first_id(&self) -> LogLineId {
            LogLineId(self.start_id)
        }

        fn get(&self, line_id: LogLineId) -> Option<&str> {
            let offset = line_id.0 - self.start_id;
            self.index_impl(offset)
        }
    fn push(&mut self, msg: &str) {
            let msg = truncate(msg, Self::MAX_LINE_LENGTH);

            let insert_location = self.push_contiguous(msg);
            let next_offset = self.start_offset + insert_location;
            self.offsets.push_back(next_offset);
        }

        fn pop(&mut self) {
            if let Some(first) = self.offsets.pop_front() {
                assert_eq!(first, self.start_offset);
                let next = self
                    .offsets
                    .front()
                    .copied()
                    .unwrap_or(self.start_offset + self.raw_data.len());
                let size = next - first;
                self.start_offset = next;
                self.start_id += 1;
                self.raw_data.drain(..size);
            }
        }
        fn iter(&self) -> impl Iterator<Item = (LogLineId, &str)> {
            (0..self.len())
                .enumerate()
                .map(|(idx, x)| (LogLineId(self.start_id + idx), self.index_impl(x).unwrap()))
        }
        fn iter_values(&self) -> impl Iterator<Item = &str> {
            (0..self.len()).map(|x| self.index_impl(x).unwrap())
        }

    fn start_id(&self) -> usize {
        self.start_id
    }

    const SUPPORT_ADD: bool = true;

    fn maybe_grow(&mut self) -> Option<&str> {
        None
    }

    fn preview<'a>(&'a mut self, msg: Option<&'a str>) -> Option<(&'a str, LogLineId)> {
        Some((msg?, LogLineId(self.start_id + self.offsets.len())))
    }

    const SUPPORT_POP: bool = true;
}


    pub struct ColumnDefinition {
        // columns
        pub col_names: Vec<String>,
        pub analyzer: Box<dyn FnMut(&str, &mut Vec<Range<u32>>)>,
    }

    pub struct AnalyzedLogLines<T:FastLogLinesTrait> {
        pub loglines: T,
        coldef: ColumnDefinition,
        // For each log line, 'cols' number of offsets within said logline
        offsets: VecDeque<Range<u32>>,
        temp: Vec<Range<u32>>,
    }

    pub trait VecDequeContExt<T> {
        fn get_range(&self, range: Range<usize>) -> &[T];
    }
    impl<T> VecDequeContExt<T> for VecDeque<T> {
        fn get_range(&self, range: Range<usize>) -> &[T] {
            let start = range.start;
            let end = range.end;
            if range.start >= range.end {
                return &[];
            }
            let slices = self.as_slices();
            let cut = slices.0.len();
            // Will panic if ranges aren't actually contiguous
            if start >= cut {
                if end-cut > slices.1.len() {
                    debug_assert!(false);
                    return &[];
                }
                &slices.1[start - cut..end - cut]
            } else {
                if end > slices.0.len() {
                    debug_assert!(false);
                    return &[];
                }
                &slices.0[start..end]
            }
        }
    }

    impl<T:FastLogLinesTrait> AnalyzedLogLines<T> {
        pub fn new(loglines: T) -> Self {
            Self {
                loglines,
                offsets: Default::default(),
                coldef: ColumnDefinition {
                    col_names: vec!["raw".to_string()],
                    analyzer: Box::new(|msg, out| {
                        out.push(0..msg.len() as u32);
                    }),
                },
                temp: vec![],
            }
        }
    }

    pub struct AnalyzedRow<'a> {
        line: &'a str,
        indices: &'a [Range<u32>],
        line_id: LogLineId,
    }

    impl<'a> AnalyzedRow<'a> {
        pub fn id(&self) -> LogLineId {
            self.line_id
        }
        pub fn cols(&'a self) -> impl Iterator<Item = &'a str> + use<'a> {
            (0..self.indices.len()).map(|idx| &self[idx])
        }
        pub fn len(&self) -> usize {
            self.indices.len()
        }
    }
    impl<'a> Index<usize> for AnalyzedRow<'a> {
        type Output = str;

        fn index(&self, index: usize) -> &Self::Output {
            if index >= self.indices.len() {
                debug_assert!(false);
                return "";
            }
            let range = self.indices[index].clone();
            if range.start == u32::MAX {
                return "";
            }
            &self.line[to_usize(range)]
        }
    }

    impl<T:FastLogLinesTrait> AnalyzedLogLines<T> {
        pub fn cols(&self) -> &[String] {
            &self.coldef.col_names
        }
        pub fn pop_front(&mut self) {
            self.loglines.pop();
            let n = self.coldef.col_names.len();
            self.offsets.drain(0..n);
        }
        pub fn position_of(&self, id: LogLineId) -> Option<usize> {
            let offset = id.0.checked_sub(self.loglines.start_id())?;
            if offset >= self.loglines.len() {
                return None;
            }
            Some(offset)
        }
        fn analyze(coldef: &mut ColumnDefinition, offsets: &mut Vec<Range<u32>>, msg: &str) {
            let n = coldef.col_names.len();
            offsets.reserve(n);
            let target = offsets.len() + coldef.col_names.len();
            (coldef.analyzer)(msg, offsets);
            while offsets.len() < target {
                offsets.push(u32::MAX..u32::MAX);
            }
        }

        // Hackpology: We call this with None when we're in fact pulling the next entry
        // from the loglines (and not actually adding one to it)
        pub fn push(&mut self, omsg: Option<&str>, mut check: impl FnMut(AnalyzedRow) -> bool) -> bool {
            self.temp.clear();
            let msg = self.loglines.preview(omsg);
            let Some((msg, line_id)) = msg else{
                return false;
            };
            Self::analyze(&mut self.coldef, &mut self.temp, msg);

            let row = AnalyzedRow {
                line: msg,
                indices: &self.temp,
                line_id,
            };
            if !check(row) {
                return true;
            }

            if let Some(omsg) = omsg {
                self.loglines.push(omsg);
            }

            self.offsets.extend(self.temp.drain(..));
            let n = self.coldef.col_names.len();
            if last_slice(&self.offsets).len() < n {
                // element not contiguous
                debug_assert!(
                    false,
                    "reserve_exact used multiple of n, this should never happen"
                );
                self.offsets.make_contiguous();
            }
            true
        }

        pub fn update(&mut self, coldef: ColumnDefinition) {
            self.coldef = coldef;
            self.offsets.clear();
            self.temp.clear();
            for item in self.loglines.iter_values() {
                (self.coldef.analyzer)(item, &mut self.temp);
            }
            self.offsets = std::mem::take(&mut self.temp).into();
        }
        pub fn get<'a>(&'a self, index: usize) -> Option<AnalyzedRow<'a>> {
            let n = self.coldef.col_names.len();
            Some(AnalyzedRow {
                line: self.loglines.index_impl(index)?,
                indices: self.offsets.get_range(index * n..(index + 1) * n),
                line_id: LogLineId(self.loglines.start_id() + index),
            })
        }
        pub fn len(&self) -> usize {
            self.loglines.len()
        }
        pub fn last<'a>(&'a self) -> AnalyzedRow<'a> {
            debug_assert!(self.loglines.len() > 0);
            let last_index = self.loglines.len() - 1;
            self.get(last_index).unwrap()
        }

        pub fn get_by_id<'a>(&'a self, id: LogLineId) -> AnalyzedRow<'a> {
            let pos = self.position_of(id).unwrap();
            self.get(pos).unwrap()
        }
        pub fn iter<'a>(&'a self) -> impl Iterator<Item = AnalyzedRow<'a>> {
            self.loglines.iter_values().enumerate().map(|(idx, line)| {
                let n = self.coldef.col_names.len();
                AnalyzedRow {
                    line,
                    indices: self.offsets.get_range(idx * n..(idx + 1) * n),
                    line_id: LogLineId(self.loglines.start_id() + idx),
                }
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{AnalyzedLogLines, AnalyzedRow, ColumnDefinition, FastLogLines, truncate, FastLogLinesTrait};

        #[test]
        fn test_analyze() {
            let mut def = AnalyzedLogLines::<FastLogLines>::new(FastLogLines::default());
            def.push(Some("hello,world"), |_| true);
            def.push(Some("tjenare,världen"), |_| true);
            def.update(ColumnDefinition {
                col_names: vec!["1".to_string(), "2".to_string()],
                analyzer: Box::new(|msg, out| {
                    let mut index = 0;
                    for sub in msg.split(',') {
                        let prev = index;
                        index += sub.len() as u32 + 1;
                        out.push(prev..index);
                    }
                }),
            });

            let analyzed = def.iter().collect::<Vec<_>>();
            assert_eq!(analyzed[0].line, "hello,world");
            assert_eq!(analyzed[0].indices, &[0..6, 6..12]);
            assert_eq!(analyzed[1].line, "tjenare,världen");
            assert_eq!(analyzed[1].indices, &[0..8, 8..17]);
        }

        #[test]
        fn test_truncate() {
            assert_eq!(truncate("abc", 2), "ab");
            assert_eq!(truncate("abc", 3), "abc");
            assert_eq!(truncate("abc", 4), "abc");
            assert_eq!(truncate("åä", 2), "å");
            assert_eq!(truncate("åä", 3), "å");
            assert_eq!(truncate("åä", 4), "åä");
            assert_eq!(truncate("åä", 5), "åä");
            assert_eq!(truncate("a", 0), "");
            assert_eq!(truncate("å", 0), "");
            assert_eq!(truncate("aå", 1), "a");
            assert_eq!(truncate("aå", 2), "a");
            assert_eq!(truncate("aå", 3), "aå");
            assert_eq!(truncate("☃︎", 1), "");
            assert_eq!(truncate("☃︎", 2), "");
            assert_eq!(truncate("☃︎", 3), "☃");
            assert_eq!(truncate("☃︎", 4), "☃");
            assert_eq!(truncate("a☃︎", 3), "a");
            assert_eq!(truncate("a☃︎", 4), "a☃");
        }
        #[test]
        fn test_big_log() {
            let mut l = FastLogLines::default();
            for x in 0..100 {
                l.push(&format!("_____{:50}______", x.to_string()));
                if x > 10 {
                    l.pop();
                }
                for i in 0..l.len() {
                    println!("{}: {} = {:?}", x, i, &l.index_impl(i));
                }
            }
        }

        #[test]
        fn test_log() {
            let mut l = FastLogLines::default();
            l.push("hello");
            l.push("world");
            assert_eq!(l.index_impl(0), Some("hello"));
            assert_eq!(l.index_impl(1), Some("world"));
            l.pop();
            assert_eq!(l.index_impl(0), Some("world"));
            l.push("world2");
            assert_eq!(l.index_impl(0), Some("world"));
            assert_eq!(l.index_impl(1), Some("world2"));
            l.pop();
            l.pop();
        }
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Default, Savefile)]
enum Window {
    #[default]
    Filter,
    Output,
}
impl Window {
    fn next(&self) -> Window {
        match self {
            Window::Filter => Self::Output,
            Window::Output => Self::Filter,
        }
    }
}

struct TpMatch {
    tp: u32,
    color_index: ColorIndex,
    hits: MatchSequence,
}

#[derive(Default, Savefile)]
struct StateConfig {
    tracepoints: Vec<TracePointData>,
    active_window: Window,
    selected_filter: Option<usize>,
    light_mode: Option<bool>,
    do_filter: bool,
    config: ParsingConfiguration,
    raw: bool,
    col_sizes: Vec<u16>,
}

struct State<T:FastLogLinesTrait> {
    fingerprint_trie: Trie<TracePoint>,
    capture_fingerprint_trie: Trie<TracePoint>,
    all_lines: AnalyzedLogLines<T>,
    total: usize,
    matching_lines: VecDeque<LogLineId>,
    generation: u64,
    selected_output: Option<usize>,
    sidescroll: usize,
    pause: bool,
    max_lines: usize,
    state_config: StateConfig,
}

impl <T:FastLogLinesTrait> State<T> {
    fn new(lines: T) -> State<T> {
        State {
            fingerprint_trie: Default::default(),
            capture_fingerprint_trie: Default::default(),
            all_lines: AnalyzedLogLines::new(lines),
            total: Default::default(),
            matching_lines: Default::default(),
            generation: Default::default(),
            selected_output: Default::default(),
            sidescroll: Default::default(),
            pause: Default::default(),
            max_lines: Default::default(),
            state_config: Default::default(),
        }

    }
}

#[derive(Default, Savefile)]
struct ParsingConfiguration {
    fields: Vec<LogField>,
}

mod simple_json {
    use std::iter::Peekable;
    use std::ops::Range;
    use std::str::Chars;

    struct Parser<'a, F: FnMut(usize, Range<u32>)> {
        orig: &'a str,
        fields: ParseBehavior<'a>,
        offset: u32,
        tokens: Peekable<Chars<'a>>,
        cb: F,
    }

    impl<'a, F: FnMut(usize, Range<u32>)> Parser<'a, F> {
        fn next(&mut self) -> Option<char> {
            let res: char = self.tokens.next()?;
            self.offset += res.len_utf8() as u32;
            Some(res)
        }
        fn peek(&mut self) -> Option<char> {
            self.tokens.peek().copied()
        }
        fn expect(&mut self, tok: char) -> Option<()> {
            let next = self.peek()?;
            if next != tok {
                return None;
            }
            self.next();
            Some(())
        }

        fn read_whitespace(&mut self) -> Option<()> {
            loop {
                let next: char = self.peek()?;
                if !next.is_whitespace() {
                    return Some(());
                }
                self.next();
            }
        }

        fn read_string(&mut self) -> Option<Range<u32>> {
            self.expect('"')?;
            let start = self.offset;
            loop {
                let cur_offset = self.offset;
                let next = self.next()?;
                if next == '"' {
                    return Some(start..cur_offset);
                }
                if next == '\\' {
                    let next = self.next()?;
                    if next == 'u' {
                        for _ in 0..4 {
                            self.next()?;
                        }
                    }
                }
            }
        }

        fn handle_key_value(&mut self, key: Range<u32>, value: Range<u32>) -> Option<()> {
            if key.end as usize > self.orig.len() {
                return None;
            }
            let key_str: &str = &self.orig[key.start as usize..key.end as usize];

            match &self.fields {
                ParseBehavior::ReportAll => (self.cb)(0, key),
                ParseBehavior::ReportFields(fields) => {
                    for (field_no, field) in fields.iter().enumerate() {
                        if field == key_str {
                            (self.cb)(field_no, value.clone())
                        }
                    }
                }
            }
            Some(())
        }

        fn parse_object(&mut self) -> Option<()> {
            self.read_whitespace()?;
            self.expect('{')?;
            self.read_whitespace()?;
            loop {
                let next = self.peek()?;
                if next == '}' {
                    self.next();
                    return Some(());
                }

                let field_name = self.read_string()?;
                self.read_whitespace()?;

                self.expect(':')?;

                self.read_whitespace()?;
                let next = self.peek()?;
                if next == '{' {
                    self.parse_object()?;
                } else if next == '"' {
                    let field_value = self.read_string()?;
                    self.handle_key_value(field_name, field_value)?;
                } else {
                    // Unsupported json value type
                    return None;
                }

                self.read_whitespace();
                let next = self.peek()?;
                if next == ',' {
                    self.next();
                    self.read_whitespace();
                } else if next != '}' {
                    return None;
                }
            }

            Some(())
        }
    }

    enum ParseBehavior<'a> {
        ReportAll,
        ReportFields(&'a [String]),
    }

    /// Parse 'input'. Provide callback for each field.
    pub fn parse<F: FnMut(usize /*field*/, Range<u32> /*value-offset*/)>(
        fields: &[String],
        input: &str,
        cb: F,
    ) {
        let mut parser = Parser {
            orig: input,
            fields: ParseBehavior::ReportFields(fields),
            offset: 0,
            tokens: input.chars().peekable(),
            cb,
        };

        _ = parser.parse_object();
    }
    pub fn parse_all<F: FnMut(usize /*field*/, Range<u32> /*value-offset*/)>(input: &str, cb: F) {
        let mut parser = Parser {
            orig: input,
            fields: ParseBehavior::ReportAll,
            offset: 0,
            tokens: input.chars().peekable(),
            cb,
        };

        _ = parser.parse_object();
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn test_kv() {
            let mut found = vec![];
            let input = r###"
                    {
                        "abc" : "def"
                    }
                "###;
            super::parse(&["abc".to_string()], input, |nr, range| {
                found.push((nr, range));
            });

            let off = input.find("def").unwrap() as u32;

            println!(
                "Returned: '{}'",
                &input[found[0].1.start as usize..found[0].1.end as usize]
            );
            assert_eq!(found, vec![(0usize, off..off + 3u32)]);
        }

        #[test]
        fn do_test1() {
            run_tests(
                r##"
            {"abc": "def"}
            "##,
                &["abc"],
                &[("abc", "def")],
            )
        }
        #[test]
        fn do_test2() {
            run_tests(
                r##"
            {"abc": "def\n"}
            "##,
                &["abc"],
                &[("abc", "def\\n")],
            )
        }
        #[test]
        fn do_test3() {
            run_tests(
                r##"
            {"fruit": "orange",
            "abc": "def"}
            "##,
                &["abc", "fruit"],
                &[("fruit", "orange"), ("abc", "def")],
            )
        }
        #[test]
        fn do_test4() {
            run_tests(
                r##"
            {   "fruit": "orange",
                "abc": "def" ,
                "sub": {
                    "car": "ford"
                }
            }
            "##,
                &["abc", "fruit", "car"],
                &[("fruit", "orange"), ("abc", "def"), ("car", "ford")],
            )
        }

        fn run_tests(input: &str, fields: &[&str], expected: &[(&str, &str)]) {
            let mut found = vec![];
            let fields = fields.iter().map(|x| x.to_string()).collect::<Vec<_>>();
            super::parse(&fields, input, |nr, range| {
                found.push((nr, range));
            });

            let off = input.find("def").unwrap() as u32;

            let mut actual = vec![];
            for item in found {
                let value = &input[item.1.start as usize..item.1.end as usize];
                let key = fields[item.0].as_str();
                actual.push((key, value));
            }

            assert_eq!(actual, expected);
        }
    }
}

impl ParsingConfiguration {
    pub fn make_analyzer(&self) -> Box<dyn FnMut(&str, &mut Vec<Range<u32>>)> {
        let fields_strings: Vec<_> = self
            .fields
            .iter()
            .map(|x| x.protocol_strings().to_string())
            .collect();
        let field_is_raw = self
            .fields
            .iter()
            .map(|x| x == &LogField::Raw)
            .collect::<Vec<_>>();
        Box::new(move |input, output| {
            let initial_index = output.len();
            for is_raw in field_is_raw.iter() {
                if *is_raw {
                    output.push(0..input.len() as u32);
                } else {
                    output.push(u32::MAX..u32::MAX);
                }
            }

            simple_json::parse(&fields_strings, input, |path, value| {
                output[initial_index + path] = value;
            });
        })
    }
}

enum ParsingConfigState {
    Enabled(Vec<(bool, LogField)>, TableState),
}
impl ParsingConfigState {
    pub fn to_configuration(self) -> ParsingConfiguration {
        match self {
            ParsingConfigState::Enabled(fields, _) => ParsingConfiguration {
                fields: fields
                    .into_iter()
                    .filter_map(|(active, field)| active.then_some(field))
                    .collect(),
            },
        }
    }
}

#[derive(Eq, PartialEq, Clone)]
struct Debounced {
    at: Instant,
    path: PathBuf,
    size: u64,
    debouncing_iterations: u64,
}

impl PartialOrd for Debounced {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Debounced {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (other.at, &other.path).cmp(&(self.at, &self.path))
    }
}

const LOGDRILLER_FILE: &str = ".logdriller.bin";
const SAVEFILE_VERSION: u32 = 1;

fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // ANSI escape sequence starts with ESC-[
            if chars.next() == Some('[') {
                // Skip until we find a letter (the command character)
                for ch in chars.by_ref() {
                    if ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else if ch == '\r' || ch == '\x08' {
            // Skip carriage return and backspace
            continue;
        } else if ch.is_control() && ch != '\t' {
            // Skip other control characters except tab
            continue;
        } else {
            result.push(ch);
        }
    }

    result
}

#[derive(Clone)]
struct BufferElement {
    data: TracePointData,
    seen_by: usize,
}

#[derive(Default)]
struct BufferInner {
    clients: Arc<()>,
    start_index: usize,
    buffer: VecDeque<BufferElement>,
}
struct ClientHandle {
    // The handle must be retained to make the client count
    // knowable
    #[allow(unused)]
    handle: Weak<()>,
    next_index: usize,
}
#[derive(Default)]
struct Buffer {
    inner: Mutex<BufferInner>,
    cond: Condvar,
}
impl Buffer {
    fn new_client(&self) -> ClientHandle {
        let inner = self.inner.lock().unwrap();
        ClientHandle {
            handle: Arc::downgrade(&inner.clients),
            next_index: inner.start_index + inner.buffer.len(),
        }
    }
    fn push(&self, data: TracePointData) {
        let mut inner = self.inner.lock().unwrap();
        inner.buffer.push_back(BufferElement { data, seen_by: 0 });
        let count = Arc::weak_count(&inner.clients);
        while let Some(front) = inner.buffer.front() {
            if front.seen_by >= count {
                inner.start_index += 1;
                inner.buffer.pop_front();
            } else {
                break;
            }
        }
        self.cond.notify_all();
    }
    fn receive(&self, client: &mut ClientHandle) -> TracePointData {
        let mut inner = self.inner.lock().unwrap();
        loop {
            if client.next_index < inner.start_index {
                client.next_index = inner.start_index;
            }
            let idx = client.next_index - inner.start_index;
            if idx < inner.buffer.len() {
                let entry = &mut inner.buffer[idx];
                entry.seen_by += 1;
                client.next_index += 1;
                return entry.data.clone();
            }
            inner = self.cond.wait(inner).unwrap();
        }
    }
}

fn scan_source(pathbuf: PathBuf, buffer: Arc<Buffer>, debug: bool) {
    let mut tasks = VecDeque::new();
    let (tx, rx) = std::sync::mpsc::channel();

    tasks.push_back(pathbuf.clone());
    let tasks = Arc::new(Mutex::new(tasks));
    let condvar = Arc::new(Condvar::new());
    let mut threads = vec![];
    let thread_count: u64 = ((std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(0usize) as u64)
        / 2)
    .max(1);
    let shift = 64 - thread_count.leading_zeros();
    let in_prog = Arc::new(AtomicUsize::new(1));
    for thread in 0..thread_count {
        let rs = OsString::from("rs");
        let tasks = tasks.clone();
        let condvar = condvar.clone();
        let in_prog = in_prog.clone();
        let mut results = IndexMap::new();
        threads.push(std::thread::spawn(move || {
            let target_dir = PathBuf::from("./target");
            let mut process_now = Vec::new();
            let mut process_soon = Vec::new();
            loop {
                let mut tasks_guard = tasks.lock().unwrap();

                let work_remaining = tasks_guard.len();
                let count = (work_remaining >> shift).max(1).min(work_remaining);

                if count == 0 {
                    if (in_prog.load(Ordering::Relaxed) as u64) <= thread {
                        condvar.notify_all();
                        return results;
                    }
                    let _guard = condvar.wait(tasks_guard).unwrap();
                    continue;
                }
                process_now.clear();
                process_now.extend(tasks_guard.drain(0..count));
                drop(tasks_guard);

                for dir in process_now.drain(..) {
                    if dir == target_dir {
                        //TODO: At some point we may want to not hardcode this
                        continue;
                    }
                    if let Ok(dir) = std::fs::read_dir(dir) {
                        for entry in dir.into_iter() {
                            if let Ok(entry) = entry
                                && let Ok(meta) = entry.metadata()
                            {
                                if meta.is_dir() {
                                    process_soon.push(entry.path());
                                }
                                if meta.is_file() {
                                    let path = entry.path();
                                    if path.extension() == Some(&rs)
                                        && let Ok(canon) = std::fs::canonicalize(path)
                                        && let Ok(contents) = std::fs::read_to_string(&canon)
                                    {
                                        results.insert(canon, contents);
                                    }
                                }
                            }
                        }
                    }
                }
                in_prog.fetch_add(process_soon.len(), Ordering::Relaxed);
                in_prog.fetch_sub(count, Ordering::Relaxed);
                let mut tasks_guard = tasks.lock().unwrap();
                let soon_count = process_soon.len() as u64;
                tasks_guard.extend(process_soon.drain(..));
                if soon_count > thread_count {
                    condvar.notify_all();
                } else {
                    for _ in 0..soon_count {
                        condvar.notify_one();
                    }
                }
            }
        }));
    }
    let mut tot_results = IndexMap::new();
    for thread in threads {
        tot_results.extend(thread.join().unwrap());
    }
    if debug {
        println!("Initial scan done");
    }

    let mut watcher = RecommendedWatcher::new(tx, Config::default()).unwrap();
    watcher.watch(&pathbuf, RecursiveMode::Recursive).unwrap();

    let mut source_line_change_tx = buffer.clone();

    let mut debouncing = BinaryHeap::<Debounced>::new();

    let rs = OsString::from("rs");
    loop {
        let mut next_debounce_at = Duration::from_secs(60);
        if let Some(top) = debouncing.peek() {
            next_debounce_at = top.at.saturating_duration_since(Instant::now());
        }

        let res = rx.recv_timeout(next_debounce_at);

        if let Ok(res) = res {
            match res {
                Ok(event) => match event.kind {
                    EventKind::Any => {}
                    EventKind::Access(_) => {}
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        for path in event.paths {
                            if path.extension() == Some(&rs)
                                && let Ok(path) = std::fs::canonicalize(path)
                                && let Ok(meta) = std::fs::metadata(&path)
                            {
                                if !meta.is_file() {
                                    continue;
                                }
                                debouncing.push(Debounced {
                                    at: Instant::now() + Duration::from_millis(500),
                                    path,
                                    size: meta.len(),
                                    debouncing_iterations: 0,
                                });
                            }
                        }
                    }
                    EventKind::Other | EventKind::Remove(_) => {}
                },
                Err(_error) => {
                    //TODO: Log somewhere? (probably add '--debuglog' option
                }
            }
        } else if let Some(mut debounced) = debouncing.pop() {
            if debug {
                println!("Bounce-checking {}", debounced.path.as_path().display());
            }

            if let Ok(meta) = std::fs::metadata(&debounced.path) {
                if meta.len() != debounced.size {
                    debounced.at = Instant::now()
                        + Duration::from_millis(
                            (100 * (1 << debounced.debouncing_iterations)).min(2000),
                        );
                    debounced.size = meta.len();
                    debounced.debouncing_iterations += 1;
                    debouncing.push(debounced);
                } else {
                    if debug {
                        println!("Path: {}", debounced.path.as_path().display());
                    }
                    if let Ok(contents) = std::fs::read_to_string(&debounced.path) {
                        match tot_results.entry(debounced.path.clone()) {
                            Entry::Occupied(mut prev_entry) => {
                                let prev_value = prev_entry.get();
                                if contents.len() < prev_value.len().saturating_sub(40)
                                    && debounced.debouncing_iterations < 3
                                {
                                    debounced.at = Instant::now() + Duration::from_millis(2000);
                                    debounced.size = meta.len();
                                    debounced.debouncing_iterations = 3;
                                    debouncing.push(debounced);
                                    continue;
                                }
                                let path = Arc::new(debounced.path);

                                parse_delta(
                                    prev_value,
                                    &contents,
                                    &path,
                                    &mut source_line_change_tx,
                                    false,
                                );

                                *prev_entry.get_mut() = contents;
                            }
                            Entry::Vacant(v) => {
                                v.insert(contents);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn run_daemon(source: PathBuf, debug: bool) {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    std::fs::write(
        ".logdriller.port",
        tcp.local_addr().unwrap().port().to_string(),
    )
    .unwrap();
    let buffer2 = Arc::new(Buffer::default());
    let buffer = buffer2.clone();
    {
        let source = source.clone();
        let buffer = buffer.clone();
        std::thread::spawn(move || {
            scan_source(source, buffer, debug);
        });
    }
    loop {
        if let Ok((mut client_stream, _)) = tcp.accept() {
            let source = source.clone();
            let buffer = buffer.clone();
            std::thread::spawn(move || {
                let mut client_obj = buffer.new_client();
                client_stream
                    .write_msg(&source.display().to_string())
                    .unwrap();
                let cmd = client_stream.read_msg::<String>().unwrap();
                if cmd == "QUIT" {
                    std::process::exit(1);
                }
                loop {
                    let next = buffer.receive(&mut client_obj);
                    if client_stream.write_msg(&next).is_err() {
                        break;
                    }
                }
            });
        }
    }
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        _ = self.0.kill();
    }
}

fn main() -> Result<()> {
    let args = LogdrillerArgs::parse();
    if !args.daemon && args.values.is_empty() && args.file.is_none() {
        eprintln!("Please provide the name of the application to run as an argument");
        std::process::exit(1);
    }
    let src = args.source.clone().unwrap_or(".".into());
    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    let pathbuf = PathBuf::from(&src);

    let mut state_config = savefile::load_file(LOGDRILLER_FILE, SAVEFILE_VERSION)
        .map(|mut state: StateConfig| {
            if state.config.fields.is_empty() {
                state.raw = true;
            }
            state
        })
        .unwrap_or_else(|_e| {
            //t.plain = true;
            let mut t = StateConfig::default();
            t.raw = true;
            t
        });

    if let Some(show_file) = &args.file {
        let state: State<MemMappedFile> = State::new(MemMappedFile::new(&show_file)?);
        inner_main(state, state_config, args, pathbuf)
    } else {
        let  state: State<FastLogLines> = State::new(FastLogLines::default());
        inner_main(state, state_config, args, pathbuf)
    }
}
fn inner_main<T:FastLogLinesTrait>(mut state: State<T>, state_config: StateConfig, args: LogdrillerArgs, pathbuf: PathBuf) -> Result<()> {
    state.state_config = state_config;
    state.rebuild_trie();
    state.reapply_parsing_config();

    state.max_lines = args.max_lines.unwrap_or(1_000_000);
    let light_mode = state.state_config.light_mode.unwrap_or_else(|| {
        terminal_light::luma()
            .map(|luma| luma > 0.6)
            .unwrap_or(false)
    });

    let mut the_child = None;

    let (diver_events_tx1, diver_events_rx) = mpsc::sync_channel(4096);
    let (string_tx1, string_rx1) = mpsc::sync_channel(STRING_CARRIER_COUNT);
    let (string_tx2, string_rx2) = mpsc::sync_channel(STRING_CARRIER_COUNT);
    let mut string_senders = [string_tx1, string_tx2];
    if args.daemon {
        run_daemon(args.source.unwrap().into(), args.debug_notify);
    }


    let mut iter = 0;

    loop {
        std::thread::sleep(Duration::from_millis(20));
        if let Ok(contents) = std::fs::read_to_string(".logdriller.port") {
            let tcpport: u16 = contents.parse::<u16>().unwrap();
            let port = tcpport;
            match TcpStream::connect(format!("127.0.0.1:{port}")) {
                Ok(mut stream) => {
                    let path = stream.read_msg::<String>().unwrap();
                    if path != pathbuf.as_path().display().to_string() {
                        stream.write_msg(&"QUIT".to_string()).unwrap();
                        continue;
                    }
                    stream.write_msg(&"GO".to_string()).unwrap();
                    let diver_events_tx = diver_events_tx1.clone();
                    std::thread::spawn(move || {
                        loop {
                            let tpdata = stream.read_msg::<TracePointData>().unwrap();

                            diver_events_tx
                                .send(DiverEvent::SourceChanged(tpdata))
                                .unwrap();
                        }
                    });
                    break;
                }
                Err(error) => {
                    if iter > 0 {
                        eprintln!("Failed to connect to server, {}", error);
                    }
                }
            }
        }
        if iter == 0 {
            std::thread::sleep(Duration::from_secs(2));
            Command::new(std::env::current_exe()?)
                .stdin(Stdio::null())
                .args(&[
                    "-s".to_string(),
                    pathbuf.as_path().display().to_string(),
                    "--daemon".to_string(),
                ])
                .spawn()
                .unwrap();
        }
        iter += 1;
        if iter > 100 {
            bail!("Failed to start background daemon");
        }
    }

    if T::SUPPORT_ADD
    {

        let mut arg_iter = args.values.into_iter();
        let cmd = arg_iter.next().expect("need at least one argument");
        let rest: Vec<_> = arg_iter.collect();
        let mut child = Command::new(&cmd)
            .args(&rest)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("LOG_JSON", "1")
            .spawn()
            .with_context(|| {
                format!(
                    "failed to spawn child process: '{}' with args: {}",
                    &cmd,
                    rest.join(" ")
                )
            })?;


        let diver_events_tx2 = diver_events_tx1.clone();
        let debug_capturer = args.debug_capturer;

        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || {
                capturer(stdout, diver_events_tx2, string_rx2, 1, debug_capturer)
            });
        }
        if let Some(stderr) = child.stderr.take() {
            std::thread::spawn(move || {
                capturer(stderr, diver_events_tx1, string_rx1, 0, debug_capturer)
            });
        }
        let child = KillOnDrop(child);

        if debug_capturer {
            std::thread::sleep(std::time::Duration::from_secs(86400));
            return Ok(());
        }

        for _ in 0..STRING_CARRIER_COUNT {
            for s in string_senders.iter_mut() {
                s.send(StringCarrier::default()).unwrap();
            }
        }
        the_child = Some(child);
    }


    let res = match catch_unwind(AssertUnwindSafe(|| {
        let terminal = ratatui::init();
        run(
            terminal,
            state,
            the_child,
            light_mode,
            diver_events_rx,
            string_senders,
        )
    })) {
        Ok(err) => err,
        Err(err) => {
            if let Some(err) = err.downcast_ref::<String>() {
                Err(anyhow!("Panic: {err}"))
            } else if let Some(err) = err.downcast_ref::<&'static str>() {
                Err(anyhow!("Panic: {err}"))
            } else {
                Err(anyhow!("panic!"))
            }
        }
    };
    ratatui::restore();

    res
}

fn analyze_logline(line: &str, pos: &mut VecDeque<Range<u32>>) {
    let value = gjson::parse(line);
    let mut message = String::new();
    let mut target = String::new();
    let mut level = String::new();
    let mut timestamp = String::new();
    let mut fields = String::new();
    value.each(|key, value| {
        match key.str() {
            "fields" => {
                value.each(|key, value| {
                    if key.str() == "message" {
                        message = value.to_string();
                    } else {
                        use std::fmt::Write;
                        write!(&mut fields, "{} = {}, ", key.str(), value.str()).unwrap();
                    }
                    true
                });
            }
            "target" => {
                target = value.to_string();
            }
            "level" => {
                level = value.to_string();
            }
            "timestamp" => {
                timestamp = value.to_string();
            }
            _ => {}
        };
        true
    });
}

trait BlockExt: Sized {
    fn highlight<T: Eq>(self, our_index: T, active_highlight: T, color_style: &ColorStyle) -> Self;
}

impl<'a> BlockExt for Block<'a> {
    fn highlight<T: Eq>(self, our_index: T, active_highlight: T, style: &ColorStyle) -> Block<'a> {
        if our_index == active_highlight {
            self.border_style(style.default_selected_style)
        } else {
            self.border_style(style.default_style)
        }
    }
}
fn popup_area(area: Rect, percent_x: u16, height: u16) -> Rect {
    let vertical = Layout::vertical([Constraint::Length(height)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

fn combine(color: &mut Rgb, other_color: Rgb) {
    color.red += other_color.red;
    color.green += other_color.green;
    color.blue += other_color.blue;
}

struct ColorScheme {
    light: bool,
    bg_color: Color,
    selected_bg_color: Color,
    base_text_color: Color,
    overflow_color: Color,
}
struct ColorStyle {
    scheme: ColorScheme,
    default_style: Style,
    default_selected_style: Style,
}
impl ColorStyle {
    pub fn new(scheme: ColorScheme) -> Self {
        Self {
            default_style: Style::from((scheme.base_text_color, scheme.bg_color)),
            default_selected_style: Style::from((scheme.base_text_color, scheme.selected_bg_color)),
            scheme,
        }
    }
    pub fn overflow_color(&self) -> Color {
        self.scheme.overflow_color
    }
    pub fn color_by_index(&self, index: ColorIndex) -> Rgb {
        let index = index.0;
        let colour = (index.wrapping_mul(57)) as f32;
        let hsl = Hsl::new(RgbHue::from_degrees(colour), 1.0, 0.4);
        use ratatui::palette::convert::FromColorUnclamped;
        let rgb = Rgb::from_color_unclamped(hsl);
        self.scheme.normalize_text_color(rgb)
    }
}
impl ColorScheme {
    pub fn new(light: bool) -> Self {
        if light {
            Self {
                light,
                bg_color: Color::Rgb(255, 255, 255),
                selected_bg_color: Color::Rgb(215, 215, 215),
                base_text_color: Color::Rgb(0, 0, 0),
                overflow_color: Color::Rgb(120, 0, 255),
            }
        } else {
            Self {
                light,
                bg_color: Color::Rgb(0, 0, 0),
                selected_bg_color: Color::Rgb(70, 70, 70),
                base_text_color: Color::Rgb(192, 192, 192),
                overflow_color: Color::Rgb(192, 0, 255),
            }
        }
    }
    fn normalize_text_color(&self, color: Rgb) -> Rgb {
        let intensity = color.red + color.green + color.blue;
        if self.light {
            if intensity > 0.7 {
                let f = 0.7 / intensity;
                Rgb::new(f * color.red, f * color.green, f * color.blue)
            } else {
                color
            }
        } else {
            // DARK
            if intensity > 3.0 {
                let f = 3.0 / intensity;
                Rgb::new(f * color.red, f * color.green, f * color.blue)
            } else if intensity < 1e-3 {
                Rgb::new(0.75, 0.75, 0.75)
            } else if intensity < 1.5 {
                let f = 1.5 / intensity;
                Rgb::new(f * color.red, f * color.green, f * color.blue)
            } else {
                color
            }
        }
    }
}

fn render_message_line_with_color(
    trie: &mut Trie<TracePoint>,
    color_style: &ColorStyle,
    mline: &str,
    bgcolor: Color,
    sidescroll: usize,
    overflow_color: Color,
) -> Line<'static> {
    let matches = get_matches(&mut *trie, mline);
    let mut message_line = Line::default();

    let byte_offset = mline
        .chars()
        .take(sidescroll)
        .map(|x| x.len_utf8())
        .sum::<usize>();

    let mut char_colors = vec![Rgb::<Srgb>::new(0.0, 0.0, 0.0); mline.len()];

    if mline.is_empty() {
        return message_line;
    }
    
    if !mline.is_empty() && byte_offset == mline.len() {
        message_line.push_span(Span::styled("←", {
            defstyle().fg(overflow_color).bg(bgcolor)
        }));
        return message_line;
    }

    if !mline.is_empty() {
        for tp_match in matches.iter() {
            let col = color_style.color_by_index(tp_match.color_index);
            for (start, end) in tp_match.hits.range.iter() {
                let end = (*end).min(char_colors.len() as u32); //TODO: Don't clamp here, it would be a bug if needed
                if *start > end {
                    debug_assert!(false);
                    continue;
                }
                for c in &mut char_colors[*start as usize..end as usize] {
                    combine(c, col);
                }
            }
        }
    }

    let mut cur_index = 0;
    for (chunk_key, contents) in char_colors.iter().chunk_by(|x| *x).into_iter() {
        let l = contents.into_iter().count();

        let mut start = cur_index;
        let end = cur_index + l;
        cur_index += l;
        if end <= byte_offset {
            continue;
        }
        if start < byte_offset {
            start = byte_offset;
        }
        if end > mline.len() {
            debug_assert!(false);
            continue;
        }
        message_line.push_span(Span::styled(mline[start..end].to_string(), {
            defstyle()
                .fg(Color::from(
                    color_style.scheme.normalize_text_color(*chunk_key),
                ))
                .bg(bgcolor)
        }));
    }
    message_line
}

#[derive(Savefile, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogField {
    Raw,
    Time,
    Severity,
    Target,
    Path,
    Field(String),
    Message,
}

impl LogField {
    fn parse(name: &str) -> LogField {
        match name {
            "" => LogField::Raw,
            "time" => LogField::Time,
            "level" => LogField::Severity,
            "target" => LogField::Target,
            "path" => LogField::Path,
            "message" => LogField::Message,
            "timestamp" => LogField::Time,
            x => LogField::Field(x.to_string()),
        }
    }
}

impl Display for LogField {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LogField::Raw => {
                write!(f, "raw")
            }
            LogField::Time => {
                write!(f, "timestamp")
            }
            LogField::Severity => {
                write!(f, "level")
            }
            LogField::Target => {
                write!(f, "target")
            }
            LogField::Path => {
                write!(f, "path")
            }
            LogField::Message => {
                write!(f, "message")
            }
            LogField::Field(name) => {
                write!(f, "@{}", name)
            }
        }
    }
}

impl LogField {
    fn protocol_strings(&self) -> &str {
        match self {
            LogField::Raw => "",
            LogField::Time => "timestamp",
            LogField::Severity => "level",
            LogField::Target => "target",
            LogField::Path => "path",
            LogField::Message => "message",
            LogField::Field(name) => name.as_str(),
        }
    }
}
fn run<T:FastLogLinesTrait>(
    mut terminal: DefaultTerminal,
    mut state: State<T>,
    mut child: Option<KillOnDrop>,
    mut light_mode: bool,
    mut program_lines: mpsc::Receiver<DiverEvent>,
    mut string_senders: [SyncSender<StringCarrier>; 2],
) -> Result<()> {
    let rows: [Row; 0] = [];

    enum GuiState {
        Normal,
        AddNewFilter(TextArea<'static>,Option<Fingerprint>/*edited fingerprint*/),
        Configure(ParsingConfigState, bool /*help*/),
        ShowHelp,
    }

    let mut color_scheme = ColorScheme::new(light_mode);
    let mut color_style = ColorStyle::new(color_scheme);
    let mut filter_table_state = TableState::default();
    let mut output_table_state = TableState::default();
    let mut last_generation = u64::MAX;
    let mut render_cnt = 0;
    let mut lastsize = Size::default();
    let mut gui_state = GuiState::Normal;

    {
        filter_table_state.select(state.state_config.selected_filter);
        output_table_state.select(state.selected_output);
    }

    let mut row_space = 0;
    let mut do_center = false;
    let mut sleep_time = 50u64;
    let mut follow = false;
    loop {
        let change;
        {
            change = mainloop(&mut state, &mut program_lines, &mut string_senders)?;
            if change {
                state.generation += 1;
            }
            let filter_table = Table::new(
                rows.clone(),
                [
                    Constraint::Length(7),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Percentage(100),
                ],
            )
            .block(
                Block::bordered()
                    .title("Filters")
                    .title_bottom("A - Add filter, O - Focus Selected")
                    .highlight(Window::Filter, state.state_config.active_window, &color_style),
            )
            .header(Row::new(vec![
                "Active", "Negative", "Capture", "Matches", "Filter",
            ]))
            .highlight_symbol(">")
            .style(color_style.default_style);

            let newsize = terminal.size()?;
            if (last_generation != state.generation || lastsize != newsize)
                && newsize.width > 20 //TODO: Render placeholder
                && newsize.height > 8
            {
                lastsize = newsize;
                terminal.draw(|frame| {
                    let main_vertical = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints(vec![Constraint::Fill(10), Constraint::Length(14)])
                        .split(frame.area());

                    let lower_split = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints(vec![Constraint::Length(20), Constraint::Fill(10)])
                        .split(main_vertical[1]);
                    let output_area: Rect = main_vertical[0];
                    let stats_area: Rect = lower_split[0];
                    let filter_area = lower_split[1];

                    row_space =
                        (output_area.height as usize).saturating_sub(if state.state_config.raw { 2 } else { 3 });
                    let matching_line_count = if state.state_config.do_filter {
                        state.matching_lines.len()
                    } else {
                        state.all_lines.len()
                    };

                    let offset;
                    let selected_opt;

                    if do_center
                        && let Some(selected) = output_table_state.selected()
                        && selected < matching_line_count
                    {
                        do_center = false;
                        offset = selected
                            .saturating_sub(row_space / 2)
                            .min(matching_line_count.saturating_sub(1));
                        *output_table_state.offset_mut() = offset;
                        selected_opt = output_table_state.selected();
                    } else if follow && matching_line_count > row_space {
                        offset =
                            matching_line_count.min(matching_line_count.saturating_sub(row_space));
                        *output_table_state.offset_mut() = offset;
                        output_table_state.select(Some(matching_line_count - 1));
                        selected_opt = output_table_state.selected();
                    } else {
                        if output_table_state.selected().unwrap_or(0) >= matching_line_count {
                            output_table_state.select(matching_line_count.checked_sub(1));
                        }
                        selected_opt = output_table_state.selected();
                        if let Some(selected) = selected_opt {
                            let offset = output_table_state
                                .offset()
                                .min(matching_line_count.saturating_sub(1));
                            if selected < offset {
                                *output_table_state.offset_mut() = selected;
                            }
                            if selected >= offset + row_space {
                                *output_table_state.offset_mut() =
                                    selected.saturating_sub(row_space.saturating_sub(1));
                            }
                        }
                        offset = output_table_state
                            .offset()
                            .min(matching_line_count.saturating_sub(1));
                    }

                    let stats = [
                        ("Total", state.total.to_string()),
                        ("Held", state.all_lines.len().to_string()),
                        ("Shown", matching_line_count.to_string()),
                        ("Status", {
                            if let Some(child) = child.as_mut() {
                                match child.0.try_wait() {
                                    Ok(Some(exit_status)) => match exit_status.code() {
                                        None => "?".to_string(),
                                        Some(code) => code.to_string(),
                                    },
                                    Ok(None) => "running".to_string(),
                                    Err(err) => err.to_string(),
                                }
                            } else {
                                "".to_string()
                            }
                        }),
                        (
                            "Filter",
                            if state.state_config.do_filter {
                                "active".to_string()
                            } else {
                                "no".to_string()
                            },
                        ),
                        ("Light", light_mode.to_string()),
                        ("Raw", state.state_config.raw.to_string()),
                    ];
                    render_cnt += 1;
                    frame.render_widget(
                        Block::bordered()
                            .title("Stats")
                            .style(color_style.default_style),
                        stats_area,
                    );
                    let mut cur_stat_area = Rect::new(
                        stats_area.x + 1,
                        stats_area.y + 1,
                        stats_area.width.saturating_sub(2),
                        1,
                    );
                    for (key, val) in stats {
                        let mut key_area = cur_stat_area;
                        key_area.width = 10;
                        let mut value_area = cur_stat_area;
                        value_area.x = 9;
                        value_area.width = value_area.width.saturating_sub(9);
                        frame.render_widget(
                            Paragraph::new(format!("{}:", key)).style(color_style.default_style),
                            key_area,
                        );
                        frame.render_widget(
                            Paragraph::new(val).style(color_style.default_style),
                            value_area,
                        );
                        cur_stat_area.y += 1;
                    }

                    let mut rows = vec![];
                    let mut fixed_output_table_state = output_table_state.clone();
                    *fixed_output_table_state.offset_mut() = 0;
                    if let Some(selected) = fixed_output_table_state.selected_mut() {
                        *selected -= offset;
                    }
                    let selected = fixed_output_table_state.selected();
                    let autosize = state.state_config.col_sizes.len() != state.all_lines.cols().len();
                    if autosize {
                        state.state_config.col_sizes.clear();
                        for col in state.all_lines.cols() {
                            state.state_config.col_sizes.push(col.chars().count() as u16);
                        }
                    }
                    if state.state_config.do_filter {
                        follow = output_table_state.selected()
                            == state.matching_lines.len().checked_sub(1);
                        for (i, mline) in state
                            .matching_lines
                            .iter()
                            .skip(offset)
                            .take(row_space)
                            .enumerate()
                        {
                            let line = mline;

                            let bgcolor = if Some(i) == selected {
                                color_style.scheme.selected_bg_color
                            } else {
                                color_style.scheme.bg_color
                            };

                            let line = state.all_lines.get_by_id(*line);

                            add_line(
                                &mut state.fingerprint_trie,
                                &mut rows,
                                line,
                                bgcolor,
                                &color_style,
                                state.sidescroll,
                                &mut state.state_config.col_sizes,
                                autosize,
                            );
                        }
                    } else {
                        follow = output_table_state.selected()
                            == Some(state.all_lines.loglines.len().saturating_sub(1));
                        for (i, line) in state
                            .all_lines
                            .iter()
                            .skip(offset)
                            .take(row_space)
                            .enumerate()
                        {
                            let bgcolor = if Some(i) == selected {
                                color_style.scheme.selected_bg_color
                            } else {
                                color_style.scheme.bg_color
                            };
                            //let msgline = render_message_line_with_color(&mut state.fingerprint_trie, &color_style, &*line, bgcolor, state.sidescroll);
                            add_line(
                                &mut state.fingerprint_trie,
                                &mut rows,
                                line,
                                bgcolor,
                                &color_style,
                                state.sidescroll,
                                &mut state.state_config.col_sizes,
                                autosize,
                            );
                        }
                    }

                    let output_cols = state
                        .state_config.col_sizes
                        .iter()
                        .map(|x| Constraint::Min(*x))
                        .collect::<Vec<_>>();

                    /*Vec::with_capacity(10);
                    if !state.plain {
                        output_cols.push(Constraint::Length(27));
                        output_cols.push(Constraint::Length(6));
                    }
                    if state.show_target {
                        output_cols.push(Constraint::Fill(10));
                    }
                    if state.fields {
                        output_cols.push(Constraint::Fill(30));
                    }
                    output_cols.push(Constraint::Fill(30));*/

                    let col_headings = state
                        .all_lines
                        .cols()
                        .iter()
                        .map(|x| x.as_str())
                        .collect::<Vec<_>>();

                    //Vec::new();

                    /*if !state.plain {
                        col_headings.push("Time");
                        col_headings.push("Level");
                    }
                    if state.show_target {
                        col_headings.push("Target");
                    }
                    if state.fields {
                        col_headings.push("Fields");
                    }
                    col_headings.push("Message");*/

                    let output_table = Table::new(rows.clone(), output_cols).block(
                        Block::bordered()
                            .title("Output")
                            .highlight(Window::Output, state.state_config.active_window, &color_style)
                            .title_bottom(format!(
                                "{} / {}, R - show raw, F - toggle filter, H - help",
                                selected_opt
                                    .map(|x| (x + 1).to_string())
                                    .unwrap_or_default(),
                                matching_line_count
                            )),
                    );
                    let output_table = if state.state_config.raw {
                        output_table
                    } else {
                        output_table.header(Row::new(col_headings))
                    };
                    let output_table = output_table
                        .highlight_symbol(">")
                        .style(color_style.default_style);

                    frame.render_stateful_widget(
                        output_table.clone().rows(rows.clone()),
                        output_area,
                        &mut fixed_output_table_state,
                    );

                    let mut rows = vec![];
                    let selected = filter_table_state
                        .selected()
                        .map(|x| x.min(state.state_config.tracepoints.len().saturating_sub(1)));
                    for (i, tracepoint) in state.state_config.tracepoints.iter().enumerate() {
                        let bgcolor = if Some(i) == selected {
                            color_style.scheme.selected_bg_color
                        } else {
                            color_style.scheme.bg_color
                        };
                        rows.push(
                            Row::new([
                                Line::raw(if tracepoint.active {
                                    "X".to_string()
                                } else {
                                    " ".to_string()
                                }),
                                Line::raw(if tracepoint.negative {
                                    "X".to_string()
                                } else {
                                    " ".to_string()
                                }),
                                Line::raw(if tracepoint.capture {
                                    "X".to_string()
                                } else {
                                    " ".to_string()
                                }),
                                Line::raw(tracepoint.matches.load(Ordering::Relaxed).to_string()),
                                Line::raw(tracepoint.fingerprint.to_string()).set_style(
                                    defstyle()
                                        .fg(color_style
                                            .color_by_index(tracepoint.tp.color_index)
                                            .into())
                                        .bg(bgcolor),
                                ),
                            ])
                            .bg(bgcolor),
                        );
                    }

                    frame.render_stateful_widget(
                        filter_table.clone().rows(rows.clone()),
                        filter_area,
                        &mut filter_table_state,
                    );

                    match &mut gui_state {
                        GuiState::Normal => {}
                        GuiState::ShowHelp => {
                            let helptext = "Keys:
q     - Exit                         o     - Step matches
↑/↓   - Scroll up/down               h     - This help
a     - Add Filter                   PgDn  - Scroll page down
Space - Enable/disable filter        PgUp  - Scroll page up
DEL   - Delete filter                l     - Light mode/dark mode
Tab   - Switch window                r     - Raw mode (don't parse output)
i     - Configure columns            f     - Enable/disable all filters
n     - Toggle negative*             Home - Go to first line
c     - Toggle capture filter**      End  - Go to last line and follow
u     - Autosize columns             s    - Freeze (throw away further output)
←/→   - Scroll rightmost column***

* exclude matching lines
** reject before buffer
*** left/right
";
                            render_help(frame, helptext, &color_style);
                            //this clears out the background
                        }
                        GuiState::AddNewFilter(text, edited) => {
                            let area = popup_area(frame.area(), 75, 3);
                            frame.render_widget(Clear, area); //this clears out the background
                            frame.render_widget(&*text, area);
                        }
                        GuiState::Configure(config_state, help) => {
                            match config_state {
                                ParsingConfigState::Enabled(fields, tablestate) => {
                                    let mut rows = Vec::new();
                                    for (active, field) in fields {
                                        let row = Row::new([
                                            Line::raw(if *active {
                                                "[X]".to_string()
                                            } else {
                                                "[ ]".to_string()
                                            }),
                                            Line::raw(field.to_string()),
                                        ]);
                                        rows.push(row);
                                    }
                                    let area = popup_area(
                                        frame.area(),
                                        75,
                                        30.min(newsize.height.saturating_sub(2)),
                                    );
                                    frame.render_widget(Clear, area); //this clears out the background

                                    let field_table = Table::new(
                                        rows.clone(),
                                        [Constraint::Length(7), Constraint::Fill(10)],
                                    )
                                    .block(
                                        Block::bordered()
                                            .title("Select fields")
                                            .title_bottom(
                                                "Enter - Apply configuration, +/- - reorder",
                                            )
                                            .highlight(
                                                Window::Filter,
                                                state.state_config.active_window,
                                                &color_style,
                                            ),
                                    )
                                    .header(Row::new(vec!["Active", "Field"]))
                                    .highlight_symbol(">")
                                    .style(color_style.default_style);

                                    frame.render_stateful_widget(
                                        field_table.clone().rows(rows.clone()),
                                        area,
                                        tablestate,
                                    );

                                    if *help {
                                        let helptext = "Configure columns
q     - Exit
↑/↓   - Scroll up/down
+/-   - Change column order
Space - Enable/disable column
Enter - Apply configuration

Note! Column support requires that the underlying application output is in json format.
";
                                        render_help(frame, helptext, &color_style);
                                    }
                                }
                            }
                        }
                    }
                })?;
                last_generation = state.generation;
            }
        }

        if change {
            sleep_time = 0;
        } else {
            sleep_time = (sleep_time + 1).min(50);
        }

        if event::poll(Duration::from_millis(sleep_time.saturating_sub(10)))? {
            let event = event::read()?;

            if let Event::Key(_) = &event {
                state.generation += 1;
            }
            if let Event::Key(KeyEvent {
                kind: KeyEventKind::Press,
                code,
                modifiers,
                ..
            }) = &event
            {
                match &mut gui_state {
                    GuiState::ShowHelp => {
                        gui_state = GuiState::Normal;
                    }
                    GuiState::Configure(confstate, help) => {
                        if *help {
                            *help = false;
                        } else {
                            match code {
                                KeyCode::Esc | KeyCode::Char('q' | 'Q') => {
                                    gui_state = GuiState::Normal;
                                }
                                KeyCode::Up => {
                                    if let ParsingConfigState::Enabled(_, tablestate) = confstate {
                                        tablestate.select_previous();
                                    }
                                }
                                KeyCode::Char('h' | 'H') => {
                                    *help = true;
                                }
                                KeyCode::Down => {
                                    if let ParsingConfigState::Enabled(_, tablestate) = confstate {
                                        tablestate.select_next();
                                    }
                                }
                                KeyCode::Char(c @ '+' | c @ '-') => {
                                    if let ParsingConfigState::Enabled(fields, tablestate) =
                                        confstate
                                        && let Some(sel) = tablestate.selected()
                                    {
                                        match *c {
                                            '+' if sel + 1 < fields.len() => {
                                                fields.swap(sel, sel + 1);
                                                tablestate.select(Some(sel + 1));
                                            }
                                            '-' if sel > 0 => {
                                                fields.swap(sel, sel - 1);
                                                tablestate.select(Some(sel - 1));
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                KeyCode::Enter => {
                                    let conf = std::mem::replace(&mut gui_state, GuiState::Normal);
                                    let GuiState::Configure(confstate,_) = conf else {
                                        unreachable!()
                                    };
                                    state.state_config.raw = false;
                                    state.apply_parsing_config(confstate.to_configuration());
                                    state.rebuild_matches();
                                    state.save();
                                }
                                KeyCode::Char(' ') => {
                                    if let ParsingConfigState::Enabled(fields, tablestate) =
                                        confstate
                                        && let Some(sel) = tablestate.selected()
                                        && let Some((active, _field)) = fields.get_mut(sel)
                                    {
                                        *active = !*active;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    GuiState::Normal => match code {
                        KeyCode::Esc | KeyCode::Char('Q') | KeyCode::Char('q') => {
                            break Ok(());
                        }
                        KeyCode::Char('H' | 'h') => {
                            gui_state = GuiState::ShowHelp;
                        }
                        KeyCode::Delete if state.state_config.active_window == Window::Filter => {
                            if let Some(index) = filter_table_state.selected() {
                                state.state_config.tracepoints.remove(index);
                                if index >= state.state_config.tracepoints.len() {
                                    let new_sel = state.state_config.tracepoints.len().checked_sub(1);
                                    state.state_config.selected_filter = new_sel;
                                    filter_table_state.select(new_sel);
                                }
                                state.rebuild_trie();
                                state.save();
                            }
                        }
                        KeyCode::Right | KeyCode::Left => match code {
                            KeyCode::Right => {
                                state.sidescroll = state.sidescroll.saturating_add(10);
                            }
                            KeyCode::Left => {
                                state.sidescroll = state.sidescroll.saturating_sub(10);
                            }
                            _ => {}
                        },
                        KeyCode::PageDown | KeyCode::PageUp => {
                            let change = match code {
                                KeyCode::PageDown => row_space as isize,
                                KeyCode::PageUp => {
                                    if state.state_config.active_window == Window::Output {
                                        follow = false;
                                    }
                                    -(row_space as isize)
                                }
                                _ => 0,
                            };
                            match state.state_config.active_window {
                                Window::Filter => {}
                                Window::Output => {
                                    if let Some(selected) = output_table_state.selected() {
                                        output_table_state
                                            .select(Some(selected.saturating_add_signed(change)));
                                    } else {
                                        output_table_state.select(Some(0));
                                    }
                                    state.selected_output = output_table_state.selected();
                                }
                            }
                        }
                        KeyCode::Home | KeyCode::End => match state.state_config.active_window {
                            Window::Filter => {}
                            Window::Output => {
                                match code {
                                    KeyCode::Home => {
                                        if state.state_config.active_window == Window::Output {
                                            follow = false;
                                        }
                                        output_table_state.select(Some(0));
                                    }
                                    KeyCode::End => {
                                        output_table_state.select(Some(usize::MAX));
                                    }
                                    _ => {}
                                }
                                state.selected_output = output_table_state.selected();
                            }
                        },
                        KeyCode::Pause | KeyCode::Char('s') | KeyCode::Char('S') => {
                            state.pause = !state.pause;
                            state.save();
                        }
                        KeyCode::Char('I') | KeyCode::Char('i') => {
                            gui_state =
                                GuiState::Configure(state.get_parsing_configuration(), false);
                        }
                        KeyCode::Char('r' | 'R') => {
                            state.state_config.raw = !state.state_config.raw;
                            state.reapply_parsing_config();
                            state.rebuild_matches();
                            state.save();
                        }
                        KeyCode::Char('F') | KeyCode::Char('f') => {
                            let was_sel = state.capture_sel();
                            state.state_config.do_filter = !state.state_config.do_filter;
                            state.restore_sel(was_sel, &mut output_table_state, &mut do_center);
                            state.save();
                        }
                        KeyCode::Char('O') | KeyCode::Char('o') => {
                            if let Some(sel) = state
                                .focus_current_tracepoint(modifiers.contains(KeyModifiers::SHIFT))
                            {
                                state.state_config.do_filter = true;
                                state.selected_output = Some(sel);
                                follow = false;
                                output_table_state.select(Some(sel));
                            }
                            state.save();
                        }
                        KeyCode::Char('l') | KeyCode::Char('L') => {
                            light_mode = !light_mode;
                            state.state_config.light_mode = Some(light_mode);
                            color_scheme = ColorScheme::new(light_mode);
                            color_style = ColorStyle::new(color_scheme);
                            state.save();
                        }
                        KeyCode::Char(c @ '+' | c @ '-') => {
                            if let Some(sel) = filter_table_state.selected()
                            {
                                match *c {
                                    '+' if sel + 1 < state.state_config.tracepoints.len() => {
                                        state.state_config.tracepoints.swap(sel, sel + 1);
                                        filter_table_state.select(Some(sel + 1));
                                    }
                                    '-' if sel > 0 => {
                                        state.state_config.tracepoints.swap(sel, sel - 1);
                                        filter_table_state.select(Some(sel - 1));
                                    }
                                    _ => {}
                                }
                            }
                        }

                        KeyCode::Char('n'|'N')
                            if state.state_config.active_window == Window::Filter =>
                        {
                            if let Some(index) = filter_table_state.selected() {
                                let was_sel = state.capture_sel();
                                if let Some(tracepoint) = state.state_config.tracepoints.get_mut(index) {
                                    tracepoint.negative = !tracepoint.negative;
                                    state.rebuild_trie();
                                    state.restore_sel(
                                        was_sel,
                                        &mut output_table_state,
                                        &mut do_center,
                                    );
                                    state.save();
                                }
                            }
                        }

                        KeyCode::Char('C' | 'c') => {
                            if let Some(index) = filter_table_state.selected() {
                                let was_sel = state.capture_sel();
                                if let Some(tracepoint) = state.state_config.tracepoints.get_mut(index) {
                                    tracepoint.capture = !tracepoint.capture;
                                    state.rebuild_trie();
                                    state.restore_sel(
                                        was_sel,
                                        &mut output_table_state,
                                        &mut do_center,
                                    );
                                    state.save();
                                }
                            }
                        }

                        KeyCode::Char(' ') => {
                            if let Some(index) = filter_table_state.selected() {
                                let was_sel = state.capture_sel();
                                if let Some(tracepoint) = state.state_config.tracepoints.get_mut(index) {
                                    tracepoint.active = !tracepoint.active;
                                    state.rebuild_trie();
                                    state.restore_sel(
                                        was_sel,
                                        &mut output_table_state,
                                        &mut do_center,
                                    );
                                    state.save();
                                }
                            }
                        }
                        KeyCode::Tab => {
                            state.state_config.active_window = state.state_config.active_window.next();
                        }
                        KeyCode::Char('u' | 'U') => {
                            state.state_config.col_sizes.clear();
                        }
                        KeyCode::Char('A') | KeyCode::Char('a') => {
                            let mut text = TextArea::default();
                            text.set_block(Block::new().borders(Borders::ALL).title("Filter"));
                            gui_state = GuiState::AddNewFilter(text, None);
                        }
                        KeyCode::Char('E') | KeyCode::Char('e') => {
                            if let Some(sel) = filter_table_state.selected() {
                                if let Some(tp) = state.state_config.tracepoints.get(sel) {
                                    let mut text = TextArea::default();
                                    text.insert_str(tp.fingerprint.to_string());
                                    text.set_block(Block::new().borders(Borders::ALL).title("Filter"));
                                    gui_state = GuiState::AddNewFilter(text, Some(tp.fingerprint.clone()));
                                }

                            }
                        }
                        KeyCode::Up => match state.state_config.active_window {
                            Window::Filter => {
                                filter_table_state.select_previous();
                                state.state_config.selected_filter = filter_table_state.selected();
                            }
                            Window::Output => {
                                follow = false;
                                output_table_state.select_previous();
                                state.selected_output = output_table_state.selected();
                            }
                        },
                        KeyCode::Down => match state.state_config.active_window {
                            Window::Filter => {
                                filter_table_state.select_next();
                                state.state_config.selected_filter = filter_table_state.selected();
                            }
                            Window::Output => {
                                output_table_state.select_next();
                                state.selected_output = output_table_state.selected();
                            }
                        },
                        _ => {}
                    },
                    GuiState::AddNewFilter(text, edited) => match code {
                        KeyCode::Esc => {
                            gui_state = GuiState::Normal;
                        }
                        KeyCode::Enter => {
                            let fingerprint = text.lines()[0].to_string();

                            state.add_tracepoint(edited.as_ref(),TracePointData {
                                fingerprint: Fingerprint::parse(&fingerprint),
                                tp: TracePoint {
                                    file: Arc::new(Default::default()),
                                    line_number: 0,
                                    tracepoint: u32::MAX,
                                    color_index: ColorIndex(0),
                                },
                                active: true,
                                capture: false,
                                negative: false,
                                matches: AtomicUsize::new(0),
                            });

                            gui_state = GuiState::Normal;
                            state.save();
                        }
                        _ => {
                            text.input(event);
                        }
                    },
                }
            }
        }
    }
}

fn render_help(frame: &mut Frame, helptext: &str, color_style: &ColorStyle) {
    let area = popup_area(frame.area(), 75, 20);
    frame.render_widget(Clear, area); //this clears out the background
    let help = Paragraph::new(helptext)
        .style(color_style.default_style)
        .block(
            Block::bordered()
                .title("Help")
                .title_bottom("Esc - close help"),
        );
    frame.render_widget(help, area); //this clears out the background
}

fn add_line<'a>(
    trie: &mut Trie<TracePoint>,
    rows: &mut Vec<Row<'a>>,
    line: AnalyzedRow<'a>,
    bgcolor: Color,
    color_style: &ColorStyle,
    sidescroll: usize,
    col_sizes: &mut Vec<u16>,
    auto_size: bool,
) {
    let mut lines = Vec::with_capacity(10);
    for (col_index, col) in line.cols().enumerate() {
        if auto_size && col_index < col_sizes.len(){
            col_sizes[col_index] = col_sizes[col_index].max(col.chars().count() as u16);
        }
        let msgline = render_message_line_with_color(
            trie,
            color_style,
            col,
            bgcolor,
            if col_index + 1 == col_sizes.len() {
                sidescroll
            } else {
                0
            },
            color_style.overflow_color(),
        );
        lines.push(msgline);
    }
    rows.push(Row::new(lines).bg(bgcolor));
}

#[cfg(test)]
mod tests {
    use crate::trie::Trie;

    #[test]
    fn dotest() {
        let mut trie = Trie::new();

        trie.push_exact("Binding to group ", 1);
        trie.push_exact("Joining multicast group  on if ", 2);
    }
}
