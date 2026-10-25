//! `instance.cfg` reading and editing for Prism Launcher and `MultiMC`.
//!
//! The two launchers write the same file in two dialects:
//!
//! - Prism Launcher saves through Qt's `QSettings` INI format: keys live in a
//!   `[General]` section and a value is quoted and backslash-escaped when it
//!   holds characters INI treats specially (`;`, `,`, `=`, `"`, `\`, leading or
//!   trailing spaces). An unquoted `,` would turn the value into a list, and an
//!   unquoted `;` starts a comment, so writing a raw value — a quoted Java
//!   agent path, a Windows path — would corrupt it.
//! - `MultiMC`'s own INI writer has no sections and escapes only `\`, `#`,
//!   newline, and tab.
//!
//! The dialect is read from the file, values are unescaped on read and escaped
//! on write by the same rules the launcher uses, and every line this module does
//! not change — comments, other sections, line endings — is preserved.

use std::fmt::Write as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    QSettings,
    MultiMc,
}

#[derive(Debug, Clone)]
pub(crate) struct IniDocument {
    lines: Vec<String>,
    dialect: Dialect,
    newline: &'static str,
    trailing_newline: bool,
}

impl IniDocument {
    pub(crate) fn parse(text: &str) -> Self {
        let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
        let lines: Vec<String> = text
            .split('\n')
            .map(|line| line.strip_suffix('\r').unwrap_or(line).to_owned())
            .collect();
        let trailing_newline = text.ends_with('\n');
        let mut lines = lines;
        if trailing_newline {
            lines.pop();
        }
        let dialect = if lines
            .iter()
            .any(|line| line.trim().eq_ignore_ascii_case("[general]"))
        {
            Dialect::QSettings
        } else {
            Dialect::MultiMc
        };
        Self {
            lines,
            dialect,
            newline,
            trailing_newline,
        }
    }

    #[cfg(test)]
    pub(crate) fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// The general-section value of `key`, unescaped.
    pub(crate) fn get(&self, key: &str) -> Option<String> {
        let index = self.find(key)?;
        let raw = self.lines[index].split_once('=')?.1;
        Some(match self.dialect {
            Dialect::QSettings => unescape_qsettings(raw),
            Dialect::MultiMc => unescape_multimc(raw.trim()),
        })
    }

    /// Sets `key` in the general section, escaping `value` for the dialect.
    pub(crate) fn set(&mut self, key: &str, value: &str) {
        let line = format!(
            "{key}={}",
            match self.dialect {
                Dialect::QSettings => escape_qsettings(value),
                Dialect::MultiMc => escape_multimc(value),
            }
        );
        if let Some(index) = self.find(key) {
            self.lines[index] = line;
            return;
        }
        match self.dialect {
            Dialect::MultiMc => self.lines.push(line),
            Dialect::QSettings => {
                let (_, end) = self.general_section();
                self.lines.insert(end, line);
            }
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut text = self.lines.join(self.newline);
        if self.trailing_newline || !text.is_empty() {
            text.push_str(self.newline);
        }
        text
    }

    /// The line range holding general-section keys: everything before the
    /// first section header, plus the `[General]` section itself.
    fn general_section(&self) -> (usize, usize) {
        if self.dialect == Dialect::MultiMc {
            return (0, self.lines.len());
        }
        let header = self
            .lines
            .iter()
            .position(|line| line.trim().eq_ignore_ascii_case("[general]"));
        let start = header.map_or(0, |index| index + 1);
        let end = self.lines[start..]
            .iter()
            .position(|line| is_section_header(line))
            .map_or(self.lines.len(), |offset| start + offset);
        // Insert before trailing blank lines so the section stays tidy.
        let mut end = end;
        while end > start && self.lines[end - 1].trim().is_empty() {
            end -= 1;
        }
        (start, end)
    }

    fn find(&self, key: &str) -> Option<usize> {
        let in_key = |line: &String| {
            let trimmed = line.trim_start();
            !trimmed.starts_with(';')
                && !trimmed.starts_with('#')
                && line
                    .split_once('=')
                    .is_some_and(|(candidate, _)| candidate.trim() == key)
        };
        match self.dialect {
            Dialect::MultiMc => self.lines.iter().position(in_key),
            Dialect::QSettings => {
                // Keys before any header belong to [General] as well.
                let mut in_general = true;
                for (index, line) in self.lines.iter().enumerate() {
                    if is_section_header(line) {
                        in_general = line.trim().eq_ignore_ascii_case("[general]");
                    } else if in_general && in_key(line) {
                        return Some(index);
                    }
                }
                None
            }
        }
    }
}

fn is_section_header(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with('[') && trimmed.ends_with(']')
}

/// `QSettings::iniEscapedString` for a string value.
pub(crate) fn escape_qsettings(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    // A string starting with `@` would read back as a variant marker.
    if value.starts_with('@') {
        escaped.push('@');
    }
    let mut needs_quotes = false;
    let mut escape_next_if_hex = false;
    for character in value.chars() {
        if matches!(character, ';' | ',' | '=') {
            needs_quotes = true;
        }
        if escape_next_if_hex && character.is_ascii_hexdigit() {
            let _ = write!(escaped, "\\x{:x}", u32::from(character));
            continue;
        }
        escape_next_if_hex = false;
        match character {
            '\0' => {
                escaped.push_str("\\0");
                escape_next_if_hex = true;
            }
            '\u{7}' => escaped.push_str("\\a"),
            '\u{8}' => escaped.push_str("\\b"),
            '\u{c}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{b}' => escaped.push_str("\\v"),
            '"' | '\\' => {
                escaped.push('\\');
                escaped.push(character);
            }
            control if u32::from(control) <= 0x1f => {
                let _ = write!(escaped, "\\x{:x}", u32::from(control));
                escape_next_if_hex = true;
            }
            other => escaped.push(other),
        }
    }
    if needs_quotes || escaped.starts_with(' ') || escaped.ends_with(' ') {
        format!("\"{escaped}\"")
    } else {
        escaped
    }
}

/// `QSettings`' reading of one value. A value that Qt would read as a list
/// (an unquoted `,`) is joined back with commas, which is how the launcher
/// itself turns it back into a string.
pub(crate) fn unescape_qsettings(raw: &str) -> String {
    let characters: Vec<char> = raw.chars().collect();
    let mut index = 0;
    while index < characters.len() && matches!(characters[index], ' ' | '\t') {
        index += 1;
    }
    let mut items: Vec<String> = Vec::new();
    let mut current = String::new();
    // Length of `current` that trailing-space trimming may not cut into: the
    // end of the last quoted or escaped character.
    let mut protected = 0;
    let mut quoted = false;
    while index < characters.len() {
        let character = characters[index];
        match character {
            '\\' => {
                index += 1;
                let Some(&code) = characters.get(index) else {
                    break;
                };
                index += 1;
                match code {
                    'a' => current.push('\u{7}'),
                    'b' => current.push('\u{8}'),
                    'f' => current.push('\u{c}'),
                    'n' => current.push('\n'),
                    'r' => current.push('\r'),
                    't' => current.push('\t'),
                    'v' => current.push('\u{b}'),
                    '"' | '?' | '\'' | '\\' => current.push(code),
                    'x' => {
                        let mut value = 0_u32;
                        while let Some(digit) = characters.get(index).and_then(|c| c.to_digit(16)) {
                            value = value.saturating_mul(16).saturating_add(digit);
                            index += 1;
                        }
                        current.extend(char::from_u32(value));
                    }
                    '0'..='7' => {
                        let mut value = code.to_digit(8).unwrap_or(0);
                        while let Some(digit) = characters.get(index).and_then(|c| c.to_digit(8)) {
                            value = value.saturating_mul(8).saturating_add(digit);
                            index += 1;
                        }
                        current.extend(char::from_u32(value));
                    }
                    other => current.push(other),
                }
                protected = current.len();
            }
            '"' => {
                quoted = !quoted;
                index += 1;
                protected = current.len();
            }
            ',' if !quoted => {
                trim_unprotected(&mut current, protected);
                items.push(std::mem::take(&mut current));
                protected = 0;
                index += 1;
                while index < characters.len() && matches!(characters[index], ' ' | '\t') {
                    index += 1;
                }
            }
            ';' if !quoted => break,
            other => {
                current.push(other);
                index += 1;
                if quoted {
                    protected = current.len();
                }
            }
        }
    }
    trim_unprotected(&mut current, protected);
    if items.is_empty() {
        // `@@` is an escaped leading `@`; a single `@` marks a Qt variant,
        // which a launcher never writes for these keys.
        if current.starts_with("@@") {
            current.remove(0);
        }
        current
    } else {
        items.push(current);
        items.join(",")
    }
}

fn trim_unprotected(value: &mut String, protected: usize) {
    while value.len() > protected && value.ends_with([' ', '\t']) {
        value.pop();
    }
}

/// `MultiMC`'s `INIFile::escape`.
pub(crate) fn escape_multimc(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\t' => escaped.push_str("\\t"),
            '\\' => escaped.push_str("\\\\"),
            '#' => escaped.push_str("\\#"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// `MultiMC`'s `INIFile::unescape`.
pub(crate) fn unescape_multimc(raw: &str) -> String {
    let mut value = String::with_capacity(raw.len());
    let mut escaping = false;
    for character in raw.chars() {
        if escaping {
            value.push(match character {
                'n' => '\n',
                't' => '\t',
                other => other,
            });
            escaping = false;
        } else if character == '\\' {
            escaping = true;
        } else {
            value.push(character);
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qsettings_values_round_trip_through_escaping() {
        for value in [
            "-Xmx4G",
            "-javaagent:\"/opt/Mine Burp/mineburp-agent.jar\"=config=\"/tmp/a b.properties\"",
            r"-javaagent:C:\Users\me\MineBurp\agent.jar=config=C:\cfg;x,y",
            " leading and trailing ",
            "@starts-with-at",
            "tab\tnewline\nnul\0end",
            "",
        ] {
            let escaped = escape_qsettings(value);
            assert_eq!(
                unescape_qsettings(&escaped),
                value,
                "escaped as `{escaped}`"
            );
        }
    }

    #[test]
    fn qsettings_quotes_what_ini_would_misread() {
        assert_eq!(escape_qsettings("a,b"), "\"a,b\"");
        assert_eq!(escape_qsettings("x;y"), "\"x;y\"");
        assert_eq!(escape_qsettings("C:\\x"), "C:\\\\x");
        assert_eq!(escape_qsettings("say \"hi\""), "say \\\"hi\\\"");
        // Reading what Qt itself writes.
        assert_eq!(unescape_qsettings("\"-Da=1, -Db=2\""), "-Da=1, -Db=2");
        assert_eq!(unescape_qsettings("plain value  ; comment"), "plain value");
        assert_eq!(unescape_qsettings("a, b"), "a,b");
    }

    #[test]
    fn edits_the_general_section_and_preserves_everything_else() {
        let text = "[General]\r\nname=Test\r\nJvmArgs=-Xmx2G\r\n\r\n[UI]\r\nJvmArgs=elsewhere\r\n";
        let mut document = IniDocument::parse(text);
        assert_eq!(document.dialect(), Dialect::QSettings);
        assert_eq!(document.get("JvmArgs").as_deref(), Some("-Xmx2G"));
        document.set("JvmArgs", "-Xmx2G -javaagent:\"/a b/agent.jar\"=config=x");
        let rendered = document.render();
        assert!(rendered.contains("\r\n[UI]\r\nJvmArgs=elsewhere\r\n"));
        assert!(
            !rendered.replace("\r\n", "").contains('\n'),
            "line endings kept"
        );
        let reparsed = IniDocument::parse(&rendered);
        assert_eq!(
            reparsed.get("JvmArgs").as_deref(),
            Some("-Xmx2G -javaagent:\"/a b/agent.jar\"=config=x")
        );

        // A missing key is added inside [General], not after [UI].
        let mut document = IniDocument::parse("[General]\nname=x\n\n[UI]\nk=v\n");
        document.set("JvmArgs", "-Da=b");
        // `=` in a value is quoted, as Qt does.
        assert_eq!(
            document.render(),
            "[General]\nname=x\nJvmArgs=\"-Da=b\"\n\n[UI]\nk=v\n"
        );
    }

    #[test]
    fn multimc_files_use_multimc_escaping() {
        let mut document = IniDocument::parse("name=Test\nJvmArgs=-Xmx6G  -Dquoted=\"a b\"\n");
        assert_eq!(document.dialect(), Dialect::MultiMc);
        assert_eq!(
            document.get("JvmArgs").as_deref(),
            Some("-Xmx6G  -Dquoted=\"a b\"")
        );
        document.set("JvmArgs", r"-javaagent:C:\agent.jar #1");
        assert!(
            document
                .render()
                .contains(r"JvmArgs=-javaagent:C:\\agent.jar \#1")
        );
        let reparsed = IniDocument::parse(&document.render());
        assert_eq!(
            reparsed.get("JvmArgs").as_deref(),
            Some(r"-javaagent:C:\agent.jar #1")
        );
    }
}
