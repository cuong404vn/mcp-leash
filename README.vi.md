# mcp-leash

**Tường lửa cho các tool của AI agent.** Viết một policy, áp dụng cho mọi MCP server, ghi log mọi lệnh gọi.

[![CI](https://github.com/cuong404vn/mcp-leash/actions/workflows/ci.yml/badge.svg)](https://github.com/cuong404vn/mcp-leash/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cuong404vn/mcp-leash/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://github.com/cuong404vn/mcp-leash/blob/main/pyproject.toml)

[English](https://github.com/cuong404vn/mcp-leash/blob/main/README.md)

AI agent ngày càng được cấp nhiều quyền (đọc ghi file, chạy shell, GitHub, cơ sở dữ liệu), và chỉ cần một đoạn prompt injection giấu trong trang web hay email là có thể điều khiển chúng làm điều bạn không muốn. mcp-leash đứng giữa MCP client và MCP server, kiểm tra từng lệnh `tools/call` theo một policy YAML và chặn những gì policy không cho phép. Lệnh bị chặn không bao giờ tới được server, và mọi quyết định đều được ghi vào audit log.

- **Không cần sửa code.** Chỉ cần thêm `mcp-leash run --policy FILE --` trước lệnh chạy server.
- **Policy dễ đọc.** Một file YAML có thể commit, review và chia sẻ.
- **Xác định.** Cùng một lệnh gọi và cùng một policy luôn cho cùng một kết quả. Không dùng LLM để ra quyết định.
- **Có audit log.** Mỗi quyết định là một dòng JSON, thông tin bí mật được che đi.
- **Nhẹ.** Thêm khoảng 0,5 ms cho mỗi lệnh gọi khi dùng policy mẫu `project` kèm audit log (trung vị của 2.000 lệnh gọi trên Windows 11, Python 3.12; [`benchmarks/overhead.py`](https://github.com/cuong404vn/mcp-leash/blob/main/benchmarks/overhead.py)).
- **Đa nền tảng.** Windows, macOS và Linux, Python 3.10 trở lên.

## Demo

![Agent thử xoá file và đọc file ngoài dự án; mcp-leash chặn cả hai, cho phép đọc file trong dự án, và ghi log mọi quyết định](https://raw.githubusercontent.com/cuong404vn/mcp-leash/main/docs/demo.gif)

Đây là một lần chạy thật, được ghi lại bằng [`examples/demo/make_demo_gif.py`](https://github.com/cuong404vn/mcp-leash/blob/main/examples/demo/make_demo_gif.py). Khi một lệnh gọi bị chặn, mcp-leash trả lời thay cho server, và model đọc được lý do:

```text
agent  → tools/call delete_file {"path": "/home/me/project/notes.txt"}
leash  ← isError: Blocked by mcp-leash (rule no-deletes): Deleting files is not permitted for agents.
server   (không bao giờ nhận được lệnh này)
```

Audit log ghi lại quyết định:

```json
{"ts":"2026-10-26T14:43:05.120Z","event":"tool_call","session":"b1f6","request_id":7,"tool":"delete_file","decision":"deny","rule":"no-deletes","reason":"Deleting files is not permitted for agents.","arguments":{"path":"/home/me/project/notes.txt"}}
```

## Cài đặt

mcp-leash được cài thẳng từ GitHub. Khi máy đã có [uv](https://docs.astral.sh/uv/) và Git:

```bash
uv tool install git+https://github.com/cuong404vn/mcp-leash
```

uv tự chọn bản Python phù hợp và đưa lệnh `mcp-leash` vào PATH. Kiểm tra bằng `mcp-leash --version`, và cập nhật về sau bằng `uv tool upgrade mcp-leash`.

Nếu không dùng uv, có thể cài bằng [pipx](https://pipx.pypa.io/) (cần Python 3.10 trở lên):

```bash
pipx install git+https://github.com/cuong404vn/mcp-leash
```

## Bắt đầu nhanh

**1. Viết policy.** Tạo policy mẫu trong thư mục hiện tại rồi chỉnh theo ý bạn:

```bash
mcp-leash init --template project
```

Mẫu `project` cho agent đọc và ghi trong thư mục dự án, đồng thời chặn xoá file, chặn đụng vào file `.env` và thư mục `.git`, chặn đường dẫn bị mã hoá như `%2e%2e/` hay `file:`, và chặn các tham số trông giống thông tin đăng nhập. Mẫu `readonly` chỉ cho phép đọc.

Với [GitHub MCP server](https://github.com/github/github-mcp-server), hãy bắt đầu từ [`policies/github.yaml`](https://github.com/cuong404vn/mcp-leash/blob/main/policies/github.yaml) và điền repository của bạn vào. Agent được đọc, bình luận, mở issue, push lên nhánh riêng và mở pull request trong đúng repository đó, nhưng không được merge, xoá, chạy hay sửa workflow, đăng gist, hay đụng tới repository nào khác. Điểm cuối cùng chặn được kiểu tấn công đã biết: một issue chứa prompt injection khiến agent chép nội dung repository riêng tư sang một nơi công khai.

**2. Cho MCP client chạy qua mcp-leash.** Thêm `mcp-leash run --policy FILE --project-dir DIR --` vào trước lệnh chạy server. Luôn truyền `--project-dir`: client thường khởi động server từ `/` hoặc thư mục cài đặt của nó, trong khi `${PROJECT_DIR}` mặc định là thư mục mà mcp-leash được khởi động.

Claude Desktop (`claude_desktop_config.json`) và Cursor (`.cursor/mcp.json` hoặc `~/.cursor/mcp.json`) dùng chung định dạng:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-leash",
      "args": [
        "run",
        "--policy", "/ABSOLUTE/PATH/TO/mcp-leash.yaml",
        "--project-dir", "/ABSOLUTE/PATH/TO/project",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/ABSOLUTE/PATH/TO/project"
      ]
    }
  }
}
```

Nếu client báo không tìm thấy `mcp-leash` (ứng dụng desktop, nhất là trên macOS, thường không nhận PATH của terminal), hãy đặt `command` là đường dẫn đầy đủ: thư mục mà lệnh `uv tool dir --bin` in ra, nối thêm `mcp-leash` (trên Windows là `mcp-leash.exe`).

File mẫu để sửa: [`examples/claude_desktop_config.json`](https://github.com/cuong404vn/mcp-leash/blob/main/examples/claude_desktop_config.json) và [`examples/cursor_mcp.json`](https://github.com/cuong404vn/mcp-leash/blob/main/examples/cursor_mcp.json).

**3. Xem một lệnh bị chặn.** Khởi động lại client và yêu cầu agent xoá một file trong dự án. Agent sẽ nhận thông báo "Blocked by mcp-leash" như trên, còn audit log (với các mẫu policy là `~/.mcp-leash/audit.jsonl`) ghi lại quyết định. Để thử policy mà không cần client:

```bash
mcp-leash check mcp-leash.yaml --tool delete_file --args '{"path": "notes.txt"}'
```

```text
decision: deny
rule: no-deletes
reason: Deleting files is not permitted for agents.
```

Muốn xem policy sẽ chặn những gì trước khi áp dụng thật, thêm `--dry-run`: mọi lệnh gọi vẫn được chuyển tiếp, còn log ghi `would_deny`.

## Policy

Các rule được kiểm tra từ trên xuống dưới, rule đầu tiên khớp sẽ quyết định. Nếu không rule nào khớp thì dùng `default`.

```yaml
version: 1
default: deny                # hành động khi không rule nào khớp: allow | deny
hide_denied_tools: true      # ẩn các tool luôn bị chặn khỏi kết quả tools/list
audit:
  path: ./mcp-leash-audit.jsonl
  redact_keys: [token, password, api_key, authorization, secret]
rules:
  - id: no-deletes
    tools: ['delete_*', 'remove_*', 'rm']
    action: deny
    reason: Deleting files is not permitted for agents.

  - id: read-inside-project
    tools: ['read_file', 'list_directory', 'search_files']
    action: allow
    when:
      - arg: path
        within: ['${PROJECT_DIR}']
```

Điều kiện hỗ trợ `equals`, `not_equals`, `in`, `starts_with`, `matches` (biểu thức chính quy) và `within` (kiểm tra đường dẫn nằm trong thư mục, có xử lý `..` và symlink). Mọi trường và toán tử được mô tả trong [policy reference](https://github.com/cuong404vn/mcp-leash/blob/main/docs/policy-reference.md) (tiếng Anh).

| Lệnh | Công dụng |
| --- | --- |
| `mcp-leash run --policy FILE [--project-dir DIR] [--dry-run] -- CMD [ARGS...]` | Chạy proxy và khởi động server thật bằng `CMD` |
| `mcp-leash validate FILE` | Kiểm tra file policy. Trả về 0 nếu hợp lệ, 2 nếu không |
| `mcp-leash check FILE --tool NAME --args JSON` | Đánh giá thử một lệnh gọi và in ra quyết định |
| `mcp-leash init [--template readonly\|project]` | Ghi policy mẫu ra `mcp-leash.yaml` |

## Cách hoạt động

mcp-leash là một lớp trung gian trong suốt cho một kết nối MCP qua stdio. Client khởi động mcp-leash, và mcp-leash khởi động server thật như một process con.

```text
MCP client                        mcp-leash                         MCP server
(Claude Desktop,      ┌─────────────────────────────────────┐     (child process)
 Cursor, agent)       │ 1. parse   strict JSON-RPC line     │
       │              │ 2. decide  evaluate(policy, tool,   │
       │  tools/call  │            arguments) -> Decision   │  allow
       ├─────────────►│ 3. audit   append one JSONL entry   ├───────────────►│
       │◄─────────────┤                                     │                │
       │  deny:       └─────────────────────────────────────┘                │
       │  isError result                                                     │
       │                                                                     │
       │◄─────────── every other message and every server response ─────────►│
                                pass through unchanged
```

- Chỉ các request `tools/call` được kiểm tra. Mọi message khác đi qua nguyên vẹn.
- Message được parse chặt chẽ: dòng có key trùng, có `NaN` hoặc sai UTF-8 sẽ bị bỏ, nên mcp-leash không bao giờ hiểu một message khác với cách server hiểu.
- Khi không chắc chắn thì chặn. Đường dẫn không phân giải được, `tools/call` sai định dạng, hoặc audit log không ghi được đều dẫn tới chặn.

## mcp-leash không phải là gì

- **Không phải sandbox.** Nó chỉ nhìn thấy lưu lượng MCP. Một tool đã được cho phép vẫn làm được mọi thứ mà server làm được, và bản thân server vẫn có thể hành xử sai. Muốn cô lập mạnh, hãy chạy server trong container hoặc dưới một tài khoản hệ điều hành bị giới hạn quyền.
- **Không phải bộ lọc nội dung.** Không có bộ phân loại AI nào. Quyết định chỉ đến từ các rule của bạn.
- **Chưa bao phủ toàn bộ MCP.** v0.1 kiểm tra `tools/call` qua stdio. Resources, prompts và sampling đi qua mà không bị kiểm tra; giao thức HTTP được lên kế hoạch cho v0.3.

[Threat model](https://github.com/cuong404vn/mcp-leash/blob/main/docs/threat-model.md) (tiếng Anh) liệt kê những gì được bảo vệ, những gì không, và các cách vượt qua đã biết.

## Lộ trình

| Phiên bản | Chủ đề |
| --- | --- |
| v0.2 | Policy mẫu đã kiểm thử cho các MCP server filesystem, GitHub và shell |
| v0.3 | Giao thức HTTP và SSE (streamable HTTP) |
| v0.4 | Phát hiện chỉ dẫn đáng ngờ trong kết quả trả về của tool |
| v0.5 | Hành động `ask`: duyệt lệnh gọi trong terminal trước khi chạy |
| v0.6 | Giới hạn tần suất và hạn mức lệnh gọi theo phiên |
| v0.7 | Lệnh `mcp-leash logs` để lọc và tổng hợp audit log |
| v0.8 | Gói TypeScript dùng cùng định dạng policy |

Tiến độ được theo dõi trong [milestones](https://github.com/cuong404vn/mcp-leash/milestones).

## Đóng góp

Rất hoan nghênh issue và pull request. Xem [CONTRIBUTING.md](https://github.com/cuong404vn/mcp-leash/blob/main/CONTRIBUTING.md) để biết cách cài môi trường phát triển. Lỗ hổng bảo mật vui lòng báo riêng theo hướng dẫn trong [SECURITY.md](https://github.com/cuong404vn/mcp-leash/blob/main/SECURITY.md).

## Giấy phép

[MIT](https://github.com/cuong404vn/mcp-leash/blob/main/LICENSE)
