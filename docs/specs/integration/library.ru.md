# Спецификация встраивания как библиотеки (Rust)

`tachyon-core` может быть напрямую встроен в приложения на Rust через крейты `core-runtime` и `core-config`.

## Основные типы и функции

### `core_config::check_str(raw: &str) -> Result<(), String>`
Проверяет сырую строку JSON-конфигурации перед запуском рантайма.

### `core_runtime::start(root: &serde_json::Value) -> anyhow::Result<BoxInstance>`
Асинхронно запускает плоскость данных (инбаунды, аутбаунды, роутер, DNS, Clash API) и возвращает дескриптор `BoxInstance`.

### `BoxInstance`
Управляет жизненным циклом запущенного экземпляра прокси.
- `inbound_addrs(&self) -> &[(String, SocketAddr)]`: Возвращает привязанные адреса всех инбаундов.
- `clash_api_addr(&self) -> Option<SocketAddr>`: Возвращает адрес контроллера Clash API.
- `reload_in_place(&mut self, new_root: &Value) -> anyhow::Result<()>`: Выполняет горячую перезагрузку правил маршрутизации, аутбаундов и DNS без разрыва активных слушателей инбаундов.
- `shutdown(&self)`: Прерывает все слушатели и задачи.
- `shutdown_wait(&mut self)`: Прерывает задачи и дожидается полного освобождения сокетов.

## Пример использования

```rust
use serde_json::Value;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_str = r#"{
        "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 1080}],
        "outbounds": [{"type": "direct"}]
    }"#;

    // 1. Валидация конфига
    core_config::check_str(config_str).map_err(|e| anyhow::anyhow!(e))?;

    // 2. Запуск экземпляра
    let root: Value = serde_json::from_str(config_str)?;
    let mut instance = core_runtime::start(&root).await?;

    println!("Слушаем на: {:?}", instance.inbound_addrs());

    // 3. Ожидание сигнала завершения
    tokio::signal::ctrl_c().await?;
    instance.shutdown_wait().await;
    Ok(())
}
```
