# Canopy TUI Mouse Selection Plan 計劃書

## Summary

本計劃書規劃在 Canopy TUI `ConnectSession` 中實作 in-app mouse selection，讓使用者透過 SSH 或 ECS Exec 進入遠端後，可以用滑鼠拖曳選取文字並複製，同時保留既有 mouse wheel local scrollback。

此方案不依賴 terminal 原生選字，而是由 Canopy 接收 mouse events 後自行處理 selection、highlight、copy，因此可以讓滑鼠滾輪與滑鼠選字共存。

## Phase 1：Mouse Event 基礎建模

- 保留既有 `MouseScroll(Up/Down)` 行為。
- 新增 left mouse `Down / Drag / Up` event model，包含 terminal absolute `row/col`。
- 只接收 left button selection 相關事件。
- `right/middle click`、plain move、horizontal scroll 仍忽略。
- 確保 mouse events 不會 forward 到遠端 PTY。

### Tests

- left down/drag/up mapping 正確。
- wheel mapping 不回歸。
- ignored mouse events 不進 app screen。
- row/col 不被交換。
- 極端座標不 panic。

## Phase 2：ConnectSession Selection State

- 在 `ConnectSessionScreen` 增加 selection state：
  - `anchor`
  - `focus`
  - `dragging`
  - `notice`
- 新增 `handle_mouse_input(...)`，只由 `Screen::ConnectSession` 呼叫。
- terminal content area 內 left down 才能開始 selection。
- drag/up 超出 terminal area 時 clamp 到可見 cell。
- overlay、copy prompt、copy_capture、closed/failed/disconnected/timed-out 狀態下 selection no-op。
- key/paste/output/scrollback/resize 清除舊 selection。

### Tests

- selection lifecycle。
- area clamp。
- overlay/copy_capture 互斥。
- disconnected 狀態 no-op。
- key/paste/output/scrollback/resize 會清除舊 selection。

## Phase 3：Text Extraction 與 Clipboard

- selection 採線性選取，不做矩形選取。
- 文字來源使用目前可見的 `vt100::Screen::cell(row, col)`。
- mouse up 時自動複製到 clipboard。
- 同列複製 substring。
- 多列用 `\n` join。
- 中間空白保留，行尾空白 trim。
- wide continuation 不重複複製。
- empty/blank-only selection 不覆蓋 clipboard。

### Tests

- 同列、多列、反向拖曳。
- CJK/wide char。
- 空白與 empty selection。
- fake clipboard success/failure。
- 後一次 selection 覆蓋前一次 clipboard。

## Phase 4：Highlight Render 與 Status UX

- `render_terminal` 先照現有 vt100 cell render，再對 selected cells 套 `theme.selected_plain_style()`。
- selected cells 保留原本文字，不清空內容。
- status bar 在 dragging 時顯示 `SELECTING`。
- copy 成功顯示 `COPIED <n> chars`。
- copy 失敗顯示 `COPY FAILED`。
- help overlay 補上 `Drag mouse: select and copy text`。

### Tests

- selected style 正確覆蓋。
- 非 selected cells 原 style 不變。
- wide continuation 不造成錯位 highlight。
- status/help text 正確。

## Phase 5：Scrollback / Alternate Screen 整合

- 非 alternate screen：
  - mouse wheel 維持現有 local scrollback。
  - selection 取目前 scrollback offset 下的可見畫面。
- alternate screen：
  - mouse wheel 不改 local scrollback。
  - 允許選取目前可見畫面文字。
- dragging selection 時 mouse wheel no-op。
- mouse up 後 mouse wheel 恢復。
- `End` 回 live view 時清除 selection。

### Tests

- wheel scrollback regression。
- alternate screen wheel no-op。
- alternate screen visible selection。
- scrollback offset 下 selection 取可見內容。
- `End` 清 selection。

## Phase 6：驗證與手動測試

### CI / Local Commands

```bash
cargo fmt --all -- --check
cargo test -p tui-client event -- --nocapture
cargo test -p tui-client connect_session -- --nocapture
cargo test -p tui-client --lib
```

若修改 shared/public type，再跑：

```bash
cargo test --workspace
```

### Manual Smoke Tests

- iTerm2 SSH session 拖曳文字，釋放後貼上確認 clipboard。
- 同 session 使用 mouse wheel 確認 local scrollback 仍正常。
- `less` / `vim` / `top` 中確認 alternate screen 可選可見文字，wheel 不誤捲 local scrollback。
- 中英文混合輸出確認 highlight 與 copied text 不錯位。
- 長 log 跨列拖曳確認 copy 順序正確。

## Assumptions

- 「滑鼠滾輪 + 滑鼠選字同時存在」採 Canopy in-app selection，不使用 terminal 原生 selection。
- mouse up 自動複製到 clipboard。
- 第一版只支援線性選取，不支援矩形/block selection。
- 第一版不 forward mouse events 到遠端 PTY。
- selection 只針對目前可見 vt100 grid，不跨不可見 scrollback 自動延伸。
