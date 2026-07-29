//! Платёж как работа с началом и концом, а не как один долгий вызов.
//!
//! Приватный платёж — это перевод оператору, обёртка суммы и запись конверта в
//! цепочку кусками, каждый со своим подтверждением. Секунд тридцать. Держать
//! всё это время открытым вызов инструмента значит заставить человека смотреть
//! в молчащий чат и гадать, живой ли агент.
//!
//! Поэтому вызов возвращается сразу с идентификатором, а работа идёт своим
//! ходом. Агент говорит «принято», потом «готово» — два сообщения вместо одной
//! паузы. Ровно эту форму рекомендуют условия бонуса ZeroClaw: *«design for
//! polling, not webhooks»*, и их эталонный победитель собран из cron-процедуры,
//! которая опрашивает состояние.
//!
//! Состояния разделены на **три**, а не на «идёт / готово», из-за одного
//! места: между переводом оператору и записью в пул деньги уже ушли. Оборвись
//! связь там — человеку нужно знать, что повторять платёж нельзя.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Сколько работа помнится после завершения.
///
/// Час, а не минуты: «прошло ли?» спрашивают не сразу. И не сутки — это память
/// процесса, а не журнал.
const RETAIN: Duration = Duration::from_secs(3600);

/// Что стало с платежом.
#[derive(Debug, Clone)]
pub enum JobState {
    /// Проверки пройдены, перевод ещё не отправлен. Денег никто не тронул.
    Preparing,
    /// Перевод оператору подтверждён; конверт пишется в цепочку.
    ///
    /// **Деньги уже списаны.** Отказ после этой точки не означает, что платёж
    /// можно повторить.
    Paid { signature: String },
    /// Готово: конверт в пуле, платёж существует.
    Done {
        signature: String,
        commitment: String,
        /// Хвост для обозревателя: `?cluster=devnet` или пусто.
        ///
        /// Без него Solscan ищет транзакцию в mainnet и отвечает «unable to
        /// locate this tx hash» — платёж выглядит несуществующим, хотя он есть,
        /// просто в другой сети.
        explorer_suffix: String,
    },
    /// Не получилось. Поле `funds_moved` отвечает на единственный вопрос,
    /// который человек задаст первым.
    Failed { reason: String, funds_moved: bool },
}

impl JobState {
    /// Текст для агента: что говорить человеку.
    pub fn describe(&self) -> String {
        match self {
            Self::Preparing => "Still preparing — nothing has been sent yet.".to_string(),
            Self::Paid { signature } => format!(
                "The transfer is confirmed and the deposit is being written to chain.\n\
                 Signature: {signature}\n\n\
                 The funds have moved. If this ends in an error, do not repeat the payment — \
                 check `receive` first."
            ),
            Self::Done {
                signature,
                commitment,
                explorer_suffix,
            } => format!(
                "Done. The payment is on chain.\n\
                 Signature: {signature}\n\
                 https://solscan.io/tx/{signature}{explorer_suffix}\n\
                 Commitment: {commitment}\n\n\
                 Say this precisely: the transaction is confirmed. Whether the recipient has \
                 collected it is something only they can see — the amount is encrypted and \
                 opens with a key their wallet alone can produce. Do not report it as \
                 delivered."
            ),
            Self::Failed {
                reason,
                funds_moved: false,
            } => format!("Failed before anything was sent: {reason}\n\nNo money moved."),
            Self::Failed {
                reason,
                funds_moved: true,
            } => format!(
                "Failed after the transfer went through: {reason}\n\n\
                 **The funds have already left.** Do not repeat this payment. Check `receive` \
                 in a minute — the deposit may well have completed anyway, since the failure \
                 was in hearing back, not in the work."
            ),
        }
    }
}

struct Entry {
    state: JobState,
    finished: Option<Instant>,
}

/// Все работы этого процесса.
///
/// В памяти: перезапуск их теряет. Это честное ограничение, и его лучше знать,
/// чем считать, будто его нет — платёж от этого не пропадает, он в цепочке;
/// теряется только возможность спросить о нём по идентификатору.
#[derive(Clone, Default)]
pub struct Jobs {
    entries: Arc<Mutex<HashMap<String, Entry>>>,
    /// Сколько работ в эту секунду в полёте.
    ///
    /// Нужен для выхода: между переводом оператору и записью конверта деньги
    /// уже списаны, а платежа ещё нет. Процесс, завершившийся в этот момент,
    /// оставляет человека без платежа и без денег — поэтому при остановке мы
    /// ждём, пока счётчик обнулится, а не выходим сразу.
    in_flight: Arc<AtomicUsize>,
}

impl Jobs {
    /// Завести работу и вернуть её идентификатор.
    pub fn start(&self) -> String {
        let id = short_id();
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut map) = self.entries.lock() {
            evict(&mut map);
            map.insert(
                id.clone(),
                Entry {
                    state: JobState::Preparing,
                    finished: None,
                },
            );
        }
        id
    }

    /// Обновить состояние. Завершённые помечаются временем для последующей
    /// уборки.
    pub fn set(&self, id: &str, state: JobState) {
        if let Ok(mut map) = self.entries.lock()
            && let Some(entry) = map.get_mut(id)
        {
            let finished = matches!(state, JobState::Done { .. } | JobState::Failed { .. });
            let was_running = entry.finished.is_none();
            entry.state = state;
            if finished {
                entry.finished = Some(Instant::now());
                if was_running {
                    self.in_flight.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }
    }

    /// Чем кончилось. `None` — такой работы нет: либо не было, либо забыта.
    pub fn get(&self, id: &str) -> Option<JobState> {
        let mut map = self.entries.lock().ok()?;
        evict(&mut map);
        map.get(id).map(|e| e.state.clone())
    }

    /// Сколько работ ещё идёт.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }
}

fn evict(map: &mut HashMap<String, Entry>) {
    map.retain(|_, e| match e.finished {
        Some(at) => at.elapsed() < RETAIN,
        None => true, // незавершённую не выбрасываем никогда
    });
}

/// Короткий идентификатор, который не стыдно продиктовать голосом.
///
/// Алфавит без похожих друг на друга символов: `0`/`O` и `1`/`l` в
/// произнесённом вслух идентификаторе — это два разных платежа.
fn short_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    const ALPHABET: &[u8] = b"23456789abcdefghjkmnpqrstuvwxyz";
    // Времени достаточно: работы живут час, в пределах одного процесса, и
    // угадывать здесь нечего — идентификатор ничего не открывает и ничем не
    // распоряжается.
    let mut n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut out = String::with_capacity(6);
    for _ in 0..6 {
        out.push(ALPHABET[(n % ALPHABET.len() as u64) as usize] as char);
        n /= ALPHABET.len() as u64;
    }
    out
}
