//! UI-only localization. The scanner, exports, profiles and history never depend on this module.
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::OnceLock};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Language {
    #[default]
    Auto,
    English,
    French,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Locale {
    English,
    French,
}

impl Language {
    pub fn resolve(self) -> Locale {
        match self {
            Self::English => Locale::English,
            Self::French => Locale::French,
            Self::Auto => {
                static SYSTEM: OnceLock<Locale> = OnceLock::new();
                *SYSTEM.get_or_init(|| {
                    let environment: Vec<_> = ["LC_ALL", "LC_MESSAGES", "LANG"]
                        .iter()
                        .filter_map(|key| std::env::var(key).ok())
                        .collect();
                    detect(&environment, &preferred_languages())
                })
            }
        }
    }
}

fn locale(code: &str) -> Option<Locale> {
    match code
        .trim()
        .split(['-', '_', '.', '@'])
        .next()?
        .to_ascii_lowercase()
        .as_str()
    {
        "fr" => Some(Locale::French),
        "en" => Some(Locale::English),
        _ => None,
    }
}

fn detect(environment: &[String], preferred: &[String]) -> Locale {
    // A neutral launcher locale must not hide the Windows display language. An explicit
    // unsupported locale falls back to English rather than selecting a different language.
    for code in environment {
        if code.trim().is_empty() || matches!(code.split('.').next(), Some("C" | "POSIX")) {
            continue;
        }
        return locale(code).unwrap_or(Locale::English);
    }
    preferred
        .iter()
        .find_map(|code| locale(code))
        .unwrap_or(Locale::English)
}

#[cfg(windows)]
fn preferred_languages() -> Vec<String> {
    use windows_sys::Win32::Globalization::{GetUserPreferredUILanguages, MUI_LANGUAGE_NAME};
    let mut count = 0;
    let mut length = 0;
    // SAFETY: the first call requests the required size; the second receives an allocated
    // UTF-16 MULTI_SZ buffer. A failure (including a changed size) returns the English fallback.
    unsafe {
        if GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME,
            &mut count,
            std::ptr::null_mut(),
            &mut length,
        ) == 0
            || length == 0
        {
            return Vec::new();
        }
        let mut buffer = vec![0u16; length as usize];
        if GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME,
            &mut count,
            buffer.as_mut_ptr(),
            &mut length,
        ) == 0
        {
            return Vec::new();
        }
        buffer
            .split(|&unit| unit == 0)
            .filter(|part| !part.is_empty())
            .map(String::from_utf16_lossy)
            .collect()
    }
}

#[cfg(not(windows))]
fn preferred_languages() -> Vec<String> {
    Vec::new()
}

fn catalog() -> &'static HashMap<&'static str, &'static str> {
    static FRENCH: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    FRENCH.get_or_init(|| {
        include_str!("i18n/fr.tsv")
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| line.split_once('\t'))
            .collect()
    })
}

impl Locale {
    pub fn text(self, source: &str) -> &str {
        match self {
            Self::English => source,
            Self::French => catalog().get(source).copied().unwrap_or(source),
        }
    }

    pub fn error(self, detail: &str) -> String {
        self.format("Error: {0}", &[self.text(detail).to_owned()])
    }

    /// Indexed placeholders allow translators to reorder arguments. Values are inserted in
    /// one pass, so a filename or device name containing `{0}` is never interpreted as text.
    pub fn format(self, source: &str, values: &[String]) -> String {
        let template = self.text(source);
        let mut output = String::with_capacity(template.len());
        let mut rest = template;
        while let Some((before, after)) = rest.split_once('{') {
            output.push_str(before);
            let Some((key, tail)) = after.split_once('}') else {
                output.push('{');
                output.push_str(after);
                return output;
            };
            if let Some(value) = key
                .parse::<usize>()
                .ok()
                .and_then(|index| values.get(index))
            {
                output.push_str(value);
            } else {
                output.push('{');
                output.push_str(key);
                output.push('}');
            }
            rest = tail;
        }
        output.push_str(rest);
        output
    }
}

/// Keep status messages as English templates plus untouched values, so switching language
/// also updates existing messages without changing data or restarting an in-progress scan.
#[derive(Clone, Debug)]
pub(super) struct Message {
    english: String,
    formatted: Option<(&'static str, Vec<String>)>,
}

impl Message {
    pub fn new(source: &'static str, values: Vec<String>) -> Self {
        Self {
            english: Locale::English.format(source, &values),
            formatted: Some((source, values)),
        }
    }

    pub fn render(&self, locale: Locale) -> String {
        match &self.formatted {
            Some((source, values)) => locale.format(source, values),
            None => locale.text(&self.english).to_owned(),
        }
    }

    pub fn phase(source: String) -> Self {
        if let Some(counts) = source
            .strip_prefix("Rechecking ")
            .and_then(|s| s.strip_suffix(" addresses without an echo reply (paced confirmation)"))
            .and_then(|s| s.split_once(" of "))
            && counts.0.parse::<usize>().is_ok()
            && counts.1.parse::<usize>().is_ok()
        {
            return Self::new(
                "Rechecking {0} of {1} addresses without an echo reply (paced confirmation)",
                vec![counts.0.to_owned(), counts.1.to_owned()],
            );
        }
        source.into()
    }
}

impl From<String> for Message {
    fn from(english: String) -> Self {
        Self {
            english,
            formatted: None,
        }
    }
}

impl From<&str> for Message {
    fn from(source: &str) -> Self {
        source.to_owned().into()
    }
}

impl std::ops::Deref for Message {
    type Target = str;
    fn deref(&self) -> &str {
        &self.english
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn automatic_detection_respects_locale_precedence_and_windows_preferences() {
        for code in ["fr", "fr-FR", "fr_CH.UTF-8", "FR-ca", "fr_BE@euro"] {
            assert_eq!(
                detect(&strings(&[code]), &strings(&["en-US"])),
                Locale::French
            );
        }
        assert_eq!(detect(&strings(&["en_GB", "fr_FR"]), &[]), Locale::English);
        assert_eq!(
            detect(&strings(&["C.UTF-8"]), &strings(&["fr-CH", "en-US"])),
            Locale::French
        );
        assert_eq!(
            detect(&strings(&["", "POSIX"]), &strings(&["de-DE", "fr-FR"])),
            Locale::French
        );
        assert_eq!(
            detect(&strings(&["de_DE", "fr_FR"]), &strings(&["fr-FR"])),
            Locale::English
        );
        assert_eq!(detect(&[], &strings(&["de-DE"])), Locale::English);
        assert_eq!(detect(&[], &[]), Locale::English);
        assert_eq!(Language::French.resolve(), Locale::French);
        assert_eq!(Language::English.resolve(), Locale::English);
    }

    #[test]
    fn catalog_has_unique_keys_and_preserves_placeholder_indices() {
        fn placeholders(text: &str) -> Vec<usize> {
            let mut indices = Vec::new();
            let mut rest = text;
            while let Some((_, after)) = rest.split_once('{') {
                let (index, tail) = after.split_once('}').expect("closed placeholder");
                indices.push(index.parse().expect("indexed placeholder"));
                rest = tail;
            }
            indices.sort_unstable();
            indices
        }
        let mut seen = std::collections::HashSet::new();
        for line in include_str!("i18n/fr.tsv")
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let (source, translated) = line.split_once('\t').expect("source<TAB>translation");
            assert!(!source.is_empty() && !translated.is_empty());
            assert!(!translated.contains('\t'));
            assert!(seen.insert(source), "duplicate: {source}");
            assert_eq!(placeholders(source), placeholders(translated), "{source}");
        }
        // This also covers labels/tooltips resolved dynamically rather than through literals.
        for fetcher in ip_scout::fetchers::Fetcher::ALL {
            for source in [fetcher.label(), fetcher.help()] {
                if source.split_whitespace().count() > 1
                    && source != "Bonjour / mDNS"
                    && source != "SSDP / UPnP"
                    && source != "MikroTik MNDP"
                {
                    assert!(
                        catalog().contains_key(source),
                        "missing fetcher translation: {source}"
                    );
                }
            }
        }
    }

    #[test]
    fn messages_can_switch_languages_without_translating_or_reinterpreting_values() {
        let device = "Ready {0} / {1} – café";
        let message = Message::new("Scanning {0}", vec![device.into()]);
        assert_eq!(
            message.render(Locale::French),
            format!("Scan de {device} en cours")
        );
        assert_eq!(
            message.render(Locale::English),
            format!("Scanning {device}")
        );
        assert_eq!(
            Locale::French.text("missing catalog entry"),
            "missing catalog entry"
        );
        assert_eq!(
            Locale::French.error("I/O {0}: denied"),
            "Erreur : I/O {0}: denied"
        );
        let phase = Message::phase(
            "Rechecking 12 of 20 addresses without an echo reply (paced confirmation)".into(),
        );
        assert!(phase.render(Locale::French).contains("12 adresses sur 20"));
        assert!(
            phase
                .render(Locale::English)
                .starts_with("Rechecking 12 of 20")
        );
        assert_eq!(
            Message::phase("unexpected engine detail".into()).render(Locale::French),
            "unexpected engine detail"
        );
    }
}
