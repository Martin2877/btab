--[[
  BTAB 蓝队流量分析插件 for Wireshark
  ==================================
  通过 REST API 调用 BTAB 后端服务 (btab server)，为 Wireshark 增加：
    - 选中帧：一键分析 / 攻击检测（SQL 注入 / XSS / Bash）/ HTTP 深度解析 / Payload 解码
    - 选中帧所在会话（TCP/HTTP 流）：逐流攻击梳理、综合分析（nuclei + webshell 关联）
    - 捕获文件攻击过程梳理（HTTP 流提取 + 逐流检测）
    - Payload 解码（base64 / base64url / url / hex / java 序列化）
    - 任意文本分析（检测 / 解码 / HTTP 解析）
    - DSL 引擎链式查询（jq / SerializationDumper / pcap / sqli / xss 插件链）

  依赖：
    - Wireshark >= 4.2（register_packet_menu；更低版本仅有 Tools 菜单）
    - curl（Windows 10+ 自带）或 PowerShell（自动回退）
    - BTAB 服务运行中：btab server（默认 http://127.0.0.1:8001）

  安装：将本文件复制到 Wireshark 个人插件目录
    Windows: %APPDATA%\Wireshark\plugins\btab.lua
    Linux:   ~/.local/lib/wireshark/plugins/btab.lua
    macOS:   ~/.config/wireshark/plugins/btab.lua
  然后 菜单 Help -> About -> Folders 确认目录，重启 Wireshark。

  配置：Edit -> Preferences -> Protocols -> BTAB -> BTAB API 地址
    或设置环境变量 BTAB_URL（如 http://192.168.1.10:8001）
--]]

local PLUGIN_NAME = "btab"
local PLUGIN_VERSION = "1.1.0"

--==================== 插件元信息 ====================
set_plugin_info({
    version = PLUGIN_VERSION,
    author = "BTAB",
    repository = "https://github.com/Martin2877/blue-team-box",
    description = "BTAB 蓝队流量分析：攻击检测 / 攻击过程梳理 / Payload 解码 / DSL 引擎",
})

--==================== 配置项 ====================
-- pcall 防护：若插件被重复加载（如 dofile 测试），Proto 名冲突不致插件失效
local btab_proto = nil
pcall(function()
    btab_proto = Proto.new(PLUGIN_NAME, "BTAB 蓝队分析")
    btab_proto.prefs["base_url"] = Pref.string(
        "BTAB API 地址", "http://127.0.0.1:8001",
        "btab server 的 HTTP 监听地址，如 http://127.0.0.1:8001")
end)

local function base_url()
    local u = os.getenv("BTAB_URL")
    if u ~= nil and u ~= "" then return u end
    local ok, pref = pcall(function() return btab_proto.prefs.base_url end)
    if ok and pref ~= nil and pref ~= "" then return tostring(pref) end
    return "http://127.0.0.1:8001"
end

--==================== 极简 JSON ====================
local json = {}

do
    local function escape_str(s)
        local map = { ['"'] = '\\"', ['\\'] = '\\\\', ['\n'] = '\\n',
                      ['\r'] = '\\r', ['\t'] = '\\t', ['\b'] = '\\b', ['\f'] = '\\f' }
        return '"' .. s:gsub('[%c"\\]', function(c) return map[c] or string.format('\\u%04x', c:byte()) end) .. '"'
    end

    local function encode_val(v, indent)
        local t = type(v)
        if t == "string" then return escape_str(v)
        elseif t == "number" then
            if v ~= v or v == math.huge or v == -math.huge then return "null" end
            return tostring(v)
        elseif t == "boolean" then return tostring(v)
        elseif t == "table" then
            local is_arr = #v > 0 or next(v) == nil
            local parts = {}
            if is_arr then
                for _, item in ipairs(v) do parts[#parts+1] = encode_val(item) end
                return "[" .. table.concat(parts, ",") .. "]"
            else
                for k, val in pairs(v) do
                    parts[#parts+1] = escape_str(tostring(k)) .. ":" .. encode_val(val)
                end
                return "{" .. table.concat(parts, ",") .. "}"
            end
        end
        return "null"
    end
    json.encode = encode_val

    local function decode_err() error("invalid json", 0) end

    local function skip_ws(s, i)
        local _, j = s:find("^[ \t\n\r]+", i)
        return j and j + 1 or i
    end

    local parse_val

    local function parse_str(s, i)
        -- i 指向开头引号
        local j = i + 1
        local buf = {}
        while j <= #s do
            local c = s:sub(j, j)
            if c == '"' then return table.concat(buf), j + 1 end
            if c == '\\' then
                local n = s:sub(j + 1, j + 1)
                if n == 'u' then
                    local hexs = s:sub(j + 2, j + 5)
                    local cp = tonumber(hexs, 16) or 0
                    -- UTF-8 编码（简化：支持 BMP）
                    if cp < 0x80 then
                        buf[#buf+1] = string.char(cp)
                    elseif cp < 0x800 then
                        buf[#buf+1] = string.char(0xC0 + math.floor(cp / 64), 0x80 + cp % 64)
                    else
                        buf[#buf+1] = string.char(0xE0 + math.floor(cp / 4096),
                            0x80 + math.floor(cp / 64) % 64, 0x80 + cp % 64)
                    end
                    j = j + 6
                else
                    local m = { n = '\n', t = '\t', r = '\r', b = '\b', f = '\f',
                                ['"'] = '"', ['\\'] = '\\', ['/'] = '/' }
                    buf[#buf+1] = m[n] or n
                    j = j + 2
                end
            else
                buf[#buf+1] = c
                j = j + 1
            end
        end
        decode_err()
    end

    local function parse_arr(s, i)
        local arr, j = {}, i + 1
        j = skip_ws(s, j)
        if s:sub(j, j) == ']' then return arr, j + 1 end
        while true do
            local v
            v, j = parse_val(s, j)
            arr[#arr+1] = v
            j = skip_ws(s, j)
            local c = s:sub(j, j)
            if c == ']' then return arr, j + 1 end
            if c ~= ',' then decode_err() end
            j = skip_ws(s, j + 1)
        end
    end

    local function parse_obj(s, i)
        local obj, j = {}, i + 1
        j = skip_ws(s, j)
        if s:sub(j, j) == '}' then return obj, j + 1 end
        while true do
            j = skip_ws(s, j)
            if s:sub(j, j) ~= '"' then decode_err() end
            local k
            k, j = parse_str(s, j)
            j = skip_ws(s, j)
            if s:sub(j, j) ~= ':' then decode_err() end
            local v
            v, j = parse_val(s, j + 1)
            obj[k] = v
            j = skip_ws(s, j)
            local c = s:sub(j, j)
            if c == '}' then return obj, j + 1 end
            if c ~= ',' then decode_err() end
            j = j + 1
        end
    end

    parse_val = function(s, i)
        i = skip_ws(s, i)
        local c = s:sub(i, i)
        if c == '"' then return parse_str(s, i) end
        if c == '{' then return parse_obj(s, i) end
        if c == '[' then return parse_arr(s, i) end
        if s:sub(i, i + 3) == 'true' then return true, i + 4 end
        if s:sub(i, i + 4) == 'false' then return false, i + 5 end
        if s:sub(i, i + 3) == 'null' then return nil, i + 4 end
        local num = s:match('^%-?%d+%.?%d*[eE]?[%+%-]?%d*', i)
        if num and #num > 0 then return tonumber(num), i + #num end
        decode_err()
    end

    function json.decode(s)
        if type(s) ~= "string" or s == "" then return nil end
        local ok, v = pcall(function() return (parse_val(s, 1)) end)
        if ok then return v end
        return nil
    end
end

--==================== HTTP（curl / powershell）====================
local is_windows = package.config:sub(1, 1) == '\\'

local function tmp_file(ext)
    local dir = os.getenv("TEMP") or os.getenv("TMP") or "/tmp"
    local sep = is_windows and "\\" or "/"
    return dir .. sep .. "btab_" .. tostring(os.time()) .. "_" ..
        tostring(math.random(100000, 999999)) .. ext
end

local function write_file(path, data)
    local f = io.open(path, "wb")
    if not f then return false end
    f:write(data)
    f:close()
    return true
end

local function run_capture(cmd)
    local h = io.popen(cmd, "r")
    if not h then return nil end
    local out = h:read("*a")
    h:close()
    return out
end

-- 返回 (http_body_string) 或 (nil, errmsg)
local function http_request(method, path, req_table)
    local url = base_url() .. path
    local body_file
    local data_opt = ""
    if req_table ~= nil then
        body_file = tmp_file(".json")
        if not write_file(body_file, json.encode(req_table)) then
            return nil, "无法写入临时文件"
        end
        if is_windows then
            data_opt = ' --data-binary @"' .. body_file .. '"'
        else
            data_opt = " --data-binary @'" .. body_file .. "'"
        end
    end

    -- 首选 curl
    local q = is_windows and '"' or "'"
    local cmd = 'curl -s -m 60 -X ' .. method ..
        ' -H ' .. q .. 'Content-Type: application/json' .. q .. data_opt ..
        ' ' .. q .. url .. q
    local out = run_capture(cmd)

    -- curl 不可用或失败时回退 PowerShell（仅 Windows）
    if (out == nil or out == "") and is_windows then
        local ps
        if body_file then
            ps = 'powershell -NoProfile -Command "$b = Get-Content -Raw ' ..
                q .. body_file .. q .. '; (Invoke-RestMethod -Uri ' .. q .. url .. q ..
                ' -Method ' .. method .. ' -ContentType ' .. q .. 'application/json' .. q ..
                ' -Body $b) | ConvertTo-Json -Depth 20 -Compress"'
        else
            ps = 'powershell -NoProfile -Command "(Invoke-RestMethod -Uri ' .. q .. url .. q ..
                ' -Method ' .. method .. ') | ConvertTo-Json -Depth 20 -Compress"'
        end
        out = run_capture(ps)
    end

    if body_file then pcall(os.remove, body_file) end
    if out == nil or out == "" then
        return nil, "HTTP 请求失败：请确认 curl 可用，且 BTAB 服务运行于 " .. base_url()
    end
    return out
end

-- 解析 BTAB 标准响应 {code, message, type, result}
local function btab_call(method, path, req_table)
    local raw, err = http_request(method, path, req_table)
    if raw == nil then return nil, err end
    local resp = json.decode(raw)
    if resp == nil then return nil, "响应解析失败: " .. raw:sub(1, 200) end
    if resp.code ~= 200 then
        return nil, "BTAB 错误: " .. tostring(resp.message)
    end
    return resp.result
end

--==================== 输出窗口 ====================
local function show_result(title, text)
    local tw = TextWindow.new(title)
    tw:set(text)
    tw:set_editable(false)
end

local function show_error(title, err)
    show_result(title, "调用失败\n\n" .. tostring(err))
end

--==================== 值提取工具 ====================
-- 把 FieldInfo.value 转为字符串；ByteArray 转 hex
local function value_to_string(v)
    local t = type(v)
    if t == "string" then return v end
    if t == "number" or t == "boolean" then return tostring(v) end
    if t == "userdata" then
        -- ByteArray: tostring 为十六进制表示
        local s = tostring(v)
        return (s:gsub("[:%s]", ""))
    end
    return tostring(v)
end

local function collect_fields(field_args)
    local fields = {}
    for _, f in ipairs(field_args) do
        if f.name and f.value ~= nil then
            local s = value_to_string(f.value)
            if s ~= nil and s ~= "" then
                -- 同名字段可能多次出现（如多值 header）
                if fields[f.name] == nil then
                    fields[f.name] = { s }
                else
                    table.insert(fields[f.name], s)
                end
            end
        end
    end
    return fields
end

local function first(fields, name)
    local v = fields[name]
    if type(v) == "table" and #v > 0 then return v[1] end
    return nil
end

local function is_hex(s)
    return s ~= nil and #s >= 2 and (#s % 2 == 0) and s:match("^[0-9a-fA-F]+$") ~= nil
end

--==================== 检测结果格式化 ====================
local function fmt_detect_result(uri_res, payload_res)
    local lines = {}
    local any_risk = false
    local function add(tag, res)
        if res == nil then return end
        if res.risk == true then any_risk = true end
        lines[#lines+1] = "===== " .. tag .. " ====="
        lines[#lines+1] = "结论: " .. tostring(res.summary or "")
        for _, eng in ipairs({ "sqli", "xss", "bash" }) do
            local item = res[eng]
            if type(item) == "table" then
                lines[#lines+1] = string.format("  [%s] found=%s available=%s code=%s",
                    eng, tostring(item.found), tostring(item.available), tostring(item.code))
                if item.message then lines[#lines+1] = "    " .. tostring(item.message) end
                if item.result then lines[#lines+1] = "    " .. tostring(item.result) end
            end
        end
        lines[#lines+1] = ""
    end
    add("URI/Header 检测", uri_res)
    add("Payload 检测", payload_res)
    return table.concat(lines, "\n"), any_risk
end

--==================== 数据包右键菜单：攻击检测 ====================
local function packet_detect(...)
    local fields = collect_fields({ ... })

    local method = first(fields, "http.request.method")
    local host = first(fields, "http.host")
    local uri = first(fields, "http.request.full_uri") or first(fields, "http.request.uri")
    local ua = first(fields, "http.user_agent")
    local file_data = first(fields, "http.file_data")
    local tcp_payload = first(fields, "tcp.payload")

    local info_lines = {}
    if method then info_lines[#info_lines+1] = "Method: " .. method end
    if host then info_lines[#info_lines+1] = "Host: " .. host end
    if uri then info_lines[#info_lines+1] = "URI: " .. uri end
    if ua then info_lines[#info_lines+1] = "UA: " .. ua end

    local uri_res, payload_res
    local errors = {}

    -- 1) URI + Header 检测
    local target = uri
    if target == nil and host then target = host end
    if target ~= nil and target ~= "" then
        local res, err = btab_call("POST", "/api/analyze/detect",
            { content = target, url_decode = true })
        if res then uri_res = res else errors[#errors+1] = "URI 检测: " .. err end
    end

    -- 2) Body / TCP payload 检测（hex）
    local hex_data = file_data or tcp_payload
    if hex_data ~= nil and is_hex(hex_data) then
        local res, err = btab_call("POST", "/api/analyze/detect",
            { content = hex_data, input_format = "hex" })
        if res then payload_res = res else errors[#errors+1] = "Payload 检测: " .. err end
    end

    if uri_res == nil and payload_res == nil then
        show_error("BTAB 攻击检测",
            (#info_lines > 0 and (table.concat(info_lines, "\n") .. "\n\n") or "") ..
            (#errors > 0 and table.concat(errors, "\n") or "该数据包无可检测内容"))
        return
    end

    local text, risk = fmt_detect_result(uri_res, payload_res)
    local title = risk and "BTAB 攻击检测 [发现风险]" or "BTAB 攻击检测 [无风险]"
    show_result(title,
        "BTAB: " .. base_url() .. "\n\n" ..
        (#info_lines > 0 and (table.concat(info_lines, "\n") .. "\n\n") or "") ..
        text ..
        (#errors > 0 and ("\n[部分检测失败]\n" .. table.concat(errors, "\n")) or ""))
end

-- http_parse 响应 → 展示行（供 packet 菜单与一键分析复用）
local function fmt_http_parse(res)
    local lines = {}
    if type(res.request) == "table" then
        lines[#lines+1] = "===== 请求概要 ====="
        if type(res.request.summary) == "table" then
            for k, v in pairs(res.request.summary) do
                lines[#lines+1] = string.format("  %s = %s", k, tostring(v))
            end
        end
        if type(res.request.url_args) == "table" then
            lines[#lines+1] = ""
            lines[#lines+1] = "===== URL 参数 ====="
            for k, v in pairs(res.request.url_args) do
                if type(v) == "table" then
                    lines[#lines+1] = string.format("  %s = %s  [%s]", k,
                        tostring(v.value), tostring(v.type))
                else
                    lines[#lines+1] = string.format("  %s = %s", k, tostring(v))
                end
            end
        end
        if type(res.request.body_args) == "table" and next(res.request.body_args) then
            lines[#lines+1] = ""
            lines[#lines+1] = "===== Body 参数 ====="
            for k, v in pairs(res.request.body_args) do
                lines[#lines+1] = string.format("  %s = %s", k, tostring(v))
            end
        end
    end
    return lines
end

--==================== 数据包右键菜单：HTTP 深度解析 ====================
local function packet_http_parse(...)
    local fields = collect_fields({ ... })
    -- 尽量重组请求行 + 头部
    local method = first(fields, "http.request.method") or "GET"
    local uri = first(fields, "http.request.uri") or "/"
    local host = first(fields, "http.host") or ""
    local ua = first(fields, "http.user_agent") or ""
    local req = method .. " " .. uri .. " HTTP/1.1\r\nHost: " .. host ..
        "\r\nUser-Agent: " .. ua .. "\r\n\r\n"

    local res, err = btab_call("POST", "/api/analyze/http_parse", { req_data = req })
    if res == nil then show_error("BTAB HTTP 解析", err) return end

    local lines = { "BTAB: " .. base_url(), "" }
    for _, l in ipairs(fmt_http_parse(res)) do lines[#lines+1] = l end
    show_result("BTAB HTTP 解析", table.concat(lines, "\n"))
end

-- decode 响应 → 展示行（供 packet 菜单 / 一键分析 / 文本分析复用）
local function fmt_decode_result(res)
    local lines = {}
    if type(res.results) == "table" then
        for _, r in ipairs(res.results) do
            if r.success then
                lines[#lines+1] = "===== " .. tostring(r.encoding) .. " ====="
                lines[#lines+1] = tostring(r.output)
                lines[#lines+1] = ""
            end
        end
    end
    if #lines == 0 then lines[#lines+1] = "所有解码器均未成功" end
    return lines
end

--==================== 数据包右键菜单：Payload 解码 ====================
local function packet_decode(...)
    local fields = collect_fields({ ... })
    local data = first(fields, "http.file_data") or first(fields, "tcp.payload") or
        first(fields, "data.data")
    if data == nil or data == "" then
        show_error("BTAB Payload 解码", "该数据包无 payload 数据")
        return
    end

    local req = { content = data }
    if is_hex(data) then req.input_format = "hex" end
    local res, err = btab_call("POST", "/api/analyze/decode", req)
    if res == nil then show_error("BTAB Payload 解码", err) return end

    local lines = { "BTAB: " .. base_url(), "", "原始(hex): " .. data:sub(1, 200) ..
        (#data > 200 and "..." or ""), "" }
    for _, l in ipairs(fmt_decode_result(res)) do lines[#lines+1] = l end
    show_result("BTAB Payload 解码", table.concat(lines, "\n"))
end

--==================== 当前捕获分析（Lua tap 提取）====================
-- 设计：不再要求用户提供 pcap 路径。Lua tap 直接读取
-- Wireshark 已打开的捕获（含未落盘的实时抓包），提取结构化
-- HTTP 流发给 BTAB 做安全检测。Wireshark 负责协议解析，
-- BTAB 负责攻击判定——各司其职。

local f_frame   = Field.new("frame.number")
local f_src     = Field.new("ip.src")
local f_sport   = Field.new("tcp.srcport")
local f_dst     = Field.new("ip.dst")
local f_dport   = Field.new("tcp.dstport")
local f_stream  = Field.new("tcp.stream")
local f_method  = Field.new("http.request.method")
local f_uri     = Field.new("http.request.uri")
local f_fulluri = Field.new("http.request.full_uri")
local f_host    = Field.new("http.host")
local f_ua      = Field.new("http.user_agent")
local f_fdata   = Field.new("http.file_data")
local f_payload = Field.new("tcp.payload")

-- 从 pinfo 提取一条流记录（仅 tap/dissector 上下文可调）
local function extract_flow(pinfo)
    local function getf(fld)
        local fi = fld()
        if fi == nil or fi.value == nil then return nil end
        return value_to_string(fi.value)
    end
    local method = getf(f_method)
    local uri = getf(f_uri)
    if method == nil and uri == nil then return nil end
    local body_hex = getf(f_fdata) or getf(f_payload)
    return {
        frame = pinfo.number or tonumber(getf(f_frame)) or 0,
        time = tostring(pinfo.abs_ts or ""),
        src_ip = getf(f_src) or "", src_port = getf(f_sport) or "",
        dst_ip = getf(f_dst) or "", dst_port = getf(f_dport) or "",
        stream = getf(f_stream) or "",
        method = method or "", uri = uri or "",
        host = getf(f_host) or "", user_agent = getf(f_ua) or "",
        body_hex = (body_hex ~= nil and is_hex(body_hex)) and body_hex or nil,
    }
end

local FLOW_BATCH = 200

local function apply_frame_filter(frames)
    if #frames == 0 then return end
    local parts = {}
    for _, n in ipairs(frames) do parts[#parts+1] = tostring(n) end
    set_filter("frame.number in {" .. table.concat(parts, " ") .. "}")
    apply_filter()
end

-- 收集完成后：分批 POST /api/analyze/flows，汇总结果并展示
local function send_flows(flows, scope)
    scope = scope or "当前捕获"
    if #flows == 0 then
        show_result("BTAB 攻击梳理", scope .. "中未发现 HTTP 请求\n\n" ..
            "提示：本功能分析 http.request 流量，非 HTTP 数据包请用右键菜单的 Payload 检测。")
        return
    end

    local all_detections = {}  -- frame -> {types, details}
    local hit_frames = {}
    local total = 0
    local errors = {}

    for i = 1, #flows, FLOW_BATCH do
        local batch = {}
        for j = i, math.min(i + FLOW_BATCH - 1, #flows) do
            batch[#batch+1] = flows[j]
        end
        local res, err = btab_call("POST", "/api/analyze/flows", { flows = batch })
        if res == nil then
            errors[#errors+1] = "批次 " .. i .. "-" .. (i + #batch - 1) .. ": " .. err
        else
            total = total + (res.summary and res.summary.total_flows or #batch)
            if type(res.flows) == "table" then
                for _, f in ipairs(res.flows) do
                    if type(f.detections) == "table" and #f.detections > 0 then
                        local kinds, details = {}, {}
                        for _, d in ipairs(f.detections) do
                            kinds[#kinds+1] = d.type
                            details[#details+1] = "[" .. tostring(d.type) .. "] " .. tostring(d.detail)
                        end
                        all_detections[f.frame] = { kinds = kinds, details = details, flow = f }
                        hit_frames[#hit_frames+1] = f.frame
                    end
                end
            end
        end
    end

    table.sort(hit_frames)
    local lines = { "BTAB 攻击梳理 [" .. scope .. "]", "",
        "BTAB: " .. base_url(),
        string.format("HTTP 请求流: %d 条   命中: %d 条", total, #hit_frames), "" }

    for _, fn in ipairs(hit_frames) do
        local d = all_detections[fn]
        local f = d.flow
        lines[#lines+1] = string.format(">>> frame %s  %s:%s -> %s:%s  %s %s://%s%s",
            tostring(fn), tostring(f.src_ip), tostring(f.src_port),
            tostring(f.dst_ip), tostring(f.dst_port), tostring(f.method),
            (f.host ~= nil and f.host ~= "") and "http" or "", tostring(f.host), tostring(f.uri))
        for _, det in ipairs(d.details) do
            lines[#lines+1] = "    " .. det
        end
        lines[#lines+1] = ""
    end

    if #errors > 0 then
        lines[#lines+1] = "[部分批次失败]"
        for _, e in ipairs(errors) do lines[#lines+1] = "  " .. e end
    end
    if #hit_frames > 0 then
        lines[#lines+1] = ""
        lines[#lines+1] = "点击下方按钮可将 display filter 应用到命中帧"
    end

    local tw = TextWindow.new(#hit_frames > 0 and
        "BTAB 攻击梳理 [" .. #hit_frames .. " 条命中]" or "BTAB 攻击梳理 [无命中]")
    tw:set(table.concat(lines, "\n"))
    tw:set_editable(false)
    if #hit_frames > 0 then
        local ok = pcall(function()
            tw:add_button("仅显示攻击帧", function() apply_frame_filter(hit_frames) end)
            tw:add_button("显示全部", function() set_filter(""); apply_filter() end)
        end)
        if not ok then
            tw:set(table.concat(lines, "\n") .. "\n\n过滤表达式（手动粘贴）:\n" ..
                "frame.number in {" .. table.concat(
                    (function() local t={} for _,n in ipairs(hit_frames) do t[#t+1]=tostring(n) end return t end)(), " ") .. "}")
        end
    end
end

--==================== 综合分析：nuclei 规则 + 跨会话关联检测 ====================
-- 告警标注：frame -> { {severity, kind, rule, title, detail}, ... }，由后置解析器写入数据包详情
local ANN = {}
local SEV_RANK = { info = 0, low = 1, medium = 2, high = 3, critical = 4 }

local alert_fields = {
    severity = ProtoField.string("btab.severity", "严重级别"),
    kind     = ProtoField.string("btab.kind", "检测类型"),
    rule     = ProtoField.string("btab.rule", "规则"),
    title    = ProtoField.string("btab.title", "标题"),
    detail   = ProtoField.string("btab.detail", "详情"),
}
local alert_experts = nil
pcall(function()
    alert_experts = {
        critical = ProtoExpert.new("btab.alert.critical", "BTAB 严重告警", expert.group.SECURITY, expert.severity.ERROR),
        high     = ProtoExpert.new("btab.alert.high", "BTAB 高危告警", expert.group.SECURITY, expert.severity.ERROR),
        medium   = ProtoExpert.new("btab.alert.medium", "BTAB 中危告警", expert.group.SECURITY, expert.severity.WARN),
        low      = ProtoExpert.new("btab.alert.low", "BTAB 低危告警", expert.group.SECURITY, expert.severity.NOTE),
        info     = ProtoExpert.new("btab.alert.info", "BTAB 信息", expert.group.SECURITY, expert.severity.CHAT),
    }
end)

-- 后置解析器：对有告警的帧添加 "BTAB 检测告警" 树、专家信息和 Info 列标记。
-- 过滤示例：btab.severity == "critical"、btab.kind contains "webshell"、btab.rule == "CVE-2021-44228"
pcall(function()
    local fl = {}
    for _, f in pairs(alert_fields) do fl[#fl+1] = f end
    btab_proto.fields = fl
    if alert_experts ~= nil then
        local el = {}
        for _, e in pairs(alert_experts) do el[#el+1] = e end
        btab_proto.experts = el
    end
    function btab_proto.dissector(tvb, pinfo, tree)
        local list = ANN[pinfo.number]
        if list == nil then return end
        local sub = tree:add(btab_proto, "BTAB 检测告警 (" .. #list .. ")")
        for _, a in ipairs(list) do
            local t = sub:add(alert_fields.title, tvb(0, 0), a.title or "")
            t:add(alert_fields.severity, tvb(0, 0), a.severity or "")
            t:add(alert_fields.kind, tvb(0, 0), a.kind or "")
            t:add(alert_fields.rule, tvb(0, 0), a.rule or "")
            if a.detail ~= nil and a.detail ~= "" then t:add(alert_fields.detail, tvb(0, 0), a.detail) end
            if alert_experts ~= nil then
                t:add_proto_expert_info(alert_experts[a.severity] or alert_experts.info, a.title or "")
            end
        end
        pcall(function()
            pinfo.cols.info:append(string.format("  [BTAB:%s %s]", list[1].severity, list[1].title))
        end)
    end
    register_postdissector(btab_proto)
end)

local f_req_line   = Field.new("http.request.line")
local f_resp_line  = Field.new("http.response.line")
local f_req_ver    = Field.new("http.request.version")
local f_resp_ver   = Field.new("http.response.version")
local f_resp_code  = Field.new("http.response.code")
local f_resp_phr   = Field.new("http.response.phrase")
local f_req_in     = Field.new("http.request_in")
local f_ip6_src    = Field.new("ipv6.src")
local f_ip6_dst    = Field.new("ipv6.dst")

local MAX_BODY_HEX = 2 * 1024 * 1024

local function all_values(fld)
    local out = {}
    for _, fi in ipairs({ fld() }) do
        if fi ~= nil and fi.value ~= nil then out[#out+1] = value_to_string(fi.value) end
    end
    return out
end

local function parse_header_lines(lines)
    local hs = {}
    for _, l in ipairs(lines) do
        l = l:gsub("[\r\n]+$", "")
        local name, val = l:match("^([^:]+):%s*(.*)$")
        if name then hs[#hs+1] = { name = name, value = val } end
    end
    return hs
end

local function body_hex()
    local fi = f_fdata()
    if fi == nil or fi.value == nil then return nil end
    local s = value_to_string(fi.value)
    if is_hex(s) and #s <= MAX_BODY_HEX then return s end
    return nil
end

-- 从一帧 HTTP 数据提取请求或响应记录
local function extract_http_row(pinfo)
    local function getf(fld)
        local fi = fld()
        if fi == nil or fi.value == nil then return nil end
        return value_to_string(fi.value)
    end
    local src = getf(f_src) or getf(f_ip6_src) or ""
    local dst = getf(f_dst) or getf(f_ip6_dst) or ""
    local frame = pinfo.number or tonumber(getf(f_frame)) or 0
    local method = getf(f_method)
    if method ~= nil then
        return { kind = "req", frame = frame, stream = getf(f_stream) or "",
            src_ip = src, dst_ip = dst,
            src_port = tonumber(getf(f_sport)) or 0, dst_port = tonumber(getf(f_dport)) or 0,
            host = getf(f_host) or "", method = method, uri = getf(f_uri) or "",
            version = getf(f_req_ver) or "", req_headers = parse_header_lines(all_values(f_req_line)),
            req_body_hex = body_hex() }
    end
    local code = getf(f_resp_code)
    if code ~= nil then
        return { kind = "resp", frame = frame, stream = getf(f_stream) or "",
            request_in = tonumber(getf(f_req_in) or ""),
            status = tonumber(code) or 0, phrase = getf(f_resp_phr) or "", version = getf(f_resp_ver) or "",
            resp_headers = parse_header_lines(all_values(f_resp_line)), resp_body_hex = body_hex() }
    end
    return nil
end

-- 将请求/响应记录配对为 Exchange（优先 http.request_in，其次同流先进先出）
local function pair_rows(rows)
    local exchanges, by_frame, pending = {}, {}, {}
    for _, r in ipairs(rows) do
        if r.kind == "req" then
            local ex = { stream = r.stream, req_frame = r.frame, src_ip = r.src_ip, dst_ip = r.dst_ip,
                src_port = r.src_port, dst_port = r.dst_port, host = r.host, method = r.method,
                uri = r.uri, version = r.version, req_headers = r.req_headers,
                req_body_hex = r.req_body_hex, has_resp = false }
            exchanges[#exchanges+1] = ex
            by_frame[r.frame] = ex
            pending[r.stream] = pending[r.stream] or {}
            table.insert(pending[r.stream], ex)
        else
            local ex = r.request_in and by_frame[r.request_in] or nil
            if ex == nil or ex.has_resp then
                local q = pending[r.stream]
                ex = q and q[1] or nil
            end
            if ex ~= nil then
                local q = pending[ex.stream]
                if q then
                    for i, e in ipairs(q) do
                        if e == ex then table.remove(q, i) break end
                    end
                end
                ex.has_resp = true
                ex.resp_frame = r.frame
                ex.status = r.status
                ex.phrase = r.phrase
                ex.resp_version = r.version
                ex.resp_headers = r.resp_headers
                ex.resp_body_hex = r.resp_body_hex
            end
        end
    end
    return exchanges
end

local function apply_filter_text(text)
    set_filter(text)
    apply_filter()
end

local function reload_capture()
    return pcall(function()
        if reload_packets ~= nil then reload_packets() elseif reload ~= nil then reload() end
    end)
end

local function report_lines(res, body_only)
    local s = res.summary or {}
    local lines = {}
    if not body_only then
        lines[#lines+1] = "BTAB 综合分析报告"
        lines[#lines+1] = ""
        lines[#lines+1] = "BTAB: " .. base_url()
    end
    lines[#lines+1] = string.format("HTTP 交互: %s   nuclei 模板: %s",
        tostring(s.exchanges), tostring(s.templates))
    lines[#lines+1] = string.format("nuclei 命中: %s   跨会话发现: %s   标注帧: %s   最高级别: %s",
        tostring(s.nuclei_findings), tostring(s.session_findings), tostring(s.annotated_frames),
        tostring((s.max_severity ~= nil and s.max_severity ~= "") and s.max_severity or "无"))
    lines[#lines+1] = ""
    local sessions = type(res.sessions) == "table" and res.sessions or {}
    lines[#lines+1] = string.format("==== 跨会话检测 (%d) ====", #sessions)
    for _, f in ipairs(sessions) do
        lines[#lines+1] = string.format("[%s] %s", string.upper(tostring(f.severity)), tostring(f.title))
        lines[#lines+1] = string.format("  目标: %s%s   来源: %s", tostring(f.host), tostring(f.uri), tostring(f.src or ""))
        if f.password ~= nil and f.password ~= "" then lines[#lines+1] = "  连接口令参数: " .. f.password end
        if f.key ~= nil and f.key ~= "" then
            lines[#lines+1] = "  密钥: " .. f.key ..
                ((f.key_frame or 0) > 0 and ("  (前置会话 frame " .. f.key_frame .. " 响应泄露)") or "  (默认密钥)")
        end
        lines[#lines+1] = "  说明: " .. tostring(f.detail)
        local fr = {}
        for _, n in ipairs(f.frames or {}) do fr[#fr+1] = tostring(n) end
        lines[#lines+1] = "  关联帧: " .. table.concat(fr, ",")
        for _, d in ipairs(f.decoded or {}) do
            lines[#lines+1] = string.format("  - #%s %s [%s]", tostring(d.frame), tostring(d.direction), tostring(d.chain))
            local plain = tostring(d.plain):gsub("\r?\n", "\n      ")
            lines[#lines+1] = "      " .. plain
        end
        lines[#lines+1] = ""
    end
    local nf = type(res.nuclei) == "table" and res.nuclei or {}
    lines[#lines+1] = string.format("==== nuclei 规则命中 (%d) ====", #nf)
    table.sort(nf, function(a, b) return (SEV_RANK[a.severity] or 0) > (SEV_RANK[b.severity] or 0) end)
    for _, f in ipairs(nf) do
        lines[#lines+1] = string.format("[%s] %s (%s)", string.upper(tostring(f.severity)), tostring(f.name), tostring(f.template_id))
        lines[#lines+1] = string.format("  frame %s%s  %s -> %s  %s %s", tostring(f.req_frame),
            (f.resp_frame or 0) > 0 and ("/" .. f.resp_frame) or "", tostring(f.src), tostring(f.dst),
            tostring(f.method), tostring(f.uri))
        if type(f.evidence) == "table" and #f.evidence > 0 then
            lines[#lines+1] = "  证据: " .. table.concat(f.evidence, " | ")
        end
        lines[#lines+1] = ""
    end
    if type(res.errors) == "table" and #res.errors > 0 then
        lines[#lines+1] = string.format("(%d 个模板加载失败，已跳过)", #res.errors)
    end
    lines[#lines+1] = ""
    lines[#lines+1] = "提示：命中帧已写入数据包详情的「BTAB 检测告警」树，并出现在 Analyze -> Expert Information；"
    lines[#lines+1] = "可用过滤器 btab.severity / btab.kind / btab.rule，或点击下方按钮。"
    return lines
end

-- 将响应中的 annotations 写入 ANN，返回标注帧数
local function apply_annotations(res)
    ANN = {}
    local count = 0
    if type(res.annotations) == "table" then
        for _, a in ipairs(res.annotations) do
            local fn = tonumber(a.frame)
            if fn then
                if ANN[fn] == nil then ANN[fn] = {}; count = count + 1 end
                table.insert(ANN[fn], a)
            end
        end
    end
    for _, list in pairs(ANN) do
        table.sort(list, function(a, b) return (SEV_RANK[a.severity] or 0) > (SEV_RANK[b.severity] or 0) end)
    end
    return count
end

local function add_alert_buttons(tw)
    pcall(function()
        tw:add_button("仅显示告警帧", function() apply_filter_text("btab.severity") end)
        tw:add_button("高危及以上", function() apply_filter_text('btab.severity == "critical" || btab.severity == "high"') end)
        tw:add_button("仅 webshell", function() apply_filter_text('btab.kind contains "webshell"') end)
        tw:add_button("显示全部", function() apply_filter_text("") end)
    end)
end

local function show_session_report(res, scope)
    local count = apply_annotations(res)
    local lines = report_lines(res)
    if scope ~= nil then lines[1] = "BTAB 综合分析报告 [" .. scope .. "]" end
    if count > 0 and not reload_capture() then
        lines[#lines+1] = "(自动刷新失败，请按 Ctrl+R 重新加载捕获以显示 BTAB 告警树)"
    end
    local tw = TextWindow.new(count > 0 and ("BTAB 综合分析 [" .. count .. " 帧告警]") or "BTAB 综合分析 [无告警]")
    tw:set(table.concat(lines, "\n"))
    tw:set_editable(false)
    if count > 0 then add_alert_buttons(tw) end
end

-- 把配对好的 HTTP 交换送 /api/analyze/session 并展示综合报告
local function session_analyze(ex, scope)
    scope = scope or "当前捕获"
    if #ex == 0 then
        show_result("BTAB 综合分析", scope .. "中未发现 HTTP 请求/响应")
        return
    end
    local res, err = btab_call("POST", "/api/analyze/session", { exchanges = ex })
    if res == nil then show_error("BTAB 综合分析", err) return end
    show_session_report(res, scope)
end

-- 按 display filter 重扫捕获，回调收到的配对交换列表（供全量/单流复用）
local function collect_exchanges(filter, cb)
    local rows = {}
    local tap = Listener.new(nil, filter)
    function tap.packet(pinfo)
        local r = extract_http_row(pinfo)
        if r then rows[#rows+1] = r end
    end
    function tap.draw()
        local ex = pair_rows(rows)
        rows = {}
        cb(ex)
    end
    retap_packets()
end

-- 按 display filter 重扫捕获，回调收到的 HTTP 请求流列表
local function collect_flows(filter, cb)
    local flows = {}
    local tap = Listener.new(nil, filter)
    function tap.packet(pinfo)
        local fl = extract_flow(pinfo)
        if fl then flows[#flows+1] = fl end
    end
    function tap.draw()
        local f = flows
        flows = {}
        cb(f)
    end
    retap_packets()
end

-- Tools → BTAB → 综合分析
local function menu_session_analysis()
    collect_exchanges("http", function(ex) session_analyze(ex, "当前捕获") end)
end

-- Tools → BTAB → 分析当前捕获
local function menu_analyze_capture()
    collect_flows("http.request", function(flows) send_flows(flows, "当前捕获") end)
end

--==================== 数据包右键菜单：会话（TCP/HTTP 流）粒度 ====================
-- 取选中包所属 tcp.stream，用 tap 过滤重扫该流，实现"会话级"分析。

local function selected_stream(fields)
    return tonumber(first(fields, "tcp.stream") or "")
end

-- 会话 → HTTP 流攻击梳理（逐请求检测）
local function packet_stream_flows(...)
    local sid = selected_stream(collect_fields({ ... }))
    if sid == nil then
        show_error("BTAB 会话攻击梳理", "该数据包不属于 TCP 会话（无 tcp.stream）")
        return
    end
    collect_flows("tcp.stream == " .. sid .. " && http.request",
        function(flows) send_flows(flows, "TCP 会话 " .. sid) end)
end

-- 会话 → 综合分析（nuclei 规则 + webshell 关联，仅该流）
local function packet_stream_session(...)
    local sid = selected_stream(collect_fields({ ... }))
    if sid == nil then
        show_error("BTAB 会话综合分析", "该数据包不属于 TCP 会话（无 tcp.stream）")
        return
    end
    collect_exchanges("tcp.stream == " .. sid .. " && http",
        function(ex) session_analyze(ex, "TCP 会话 " .. sid) end)
end

--==================== 数据包右键菜单：一键分析 ====================
-- 对选中帧自动执行全部适用分析（URI/Header 检测、HTTP 解析、Payload 检测+解码），
-- 若属于含 HTTP 的 TCP 会话，再对该流做综合分析；所有结果合入同一窗口。
local function packet_oneclick(...)
    local fields = collect_fields({ ... })

    local method = first(fields, "http.request.method")
    local host = first(fields, "http.host")
    local uri = first(fields, "http.request.full_uri") or first(fields, "http.request.uri")
    local ua = first(fields, "http.user_agent")
    local file_data = first(fields, "http.file_data")
    local tcp_payload = first(fields, "tcp.payload")

    local lines = { "BTAB 一键分析", "", "BTAB: " .. base_url(), "" }
    if method then lines[#lines+1] = "Method: " .. method end
    if host then lines[#lines+1] = "Host: " .. host end
    if uri then lines[#lines+1] = "URI: " .. uri end
    if ua then lines[#lines+1] = "UA: " .. ua end
    lines[#lines+1] = ""

    local errors = {}
    local did = 0

    -- 1) URI/Header 攻击检测
    local target = uri or host
    if target ~= nil and target ~= "" then
        local res, err = btab_call("POST", "/api/analyze/detect",
            { content = target, url_decode = true })
        if res then
            lines[#lines+1] = fmt_detect_result(res, nil)
            did = did + 1
        else
            errors[#errors+1] = "URI 检测: " .. err
        end
    end

    -- 2) HTTP 深度解析
    if method ~= nil then
        local req = method .. " " .. (uri or "/") .. " HTTP/1.1\r\nHost: " ..
            (host or "") .. "\r\nUser-Agent: " .. (ua or "") .. "\r\n\r\n"
        local res, err = btab_call("POST", "/api/analyze/http_parse", { req_data = req })
        if res then
            lines[#lines+1] = "===== HTTP 解析 ====="
            for _, l in ipairs(fmt_http_parse(res)) do lines[#lines+1] = l end
            lines[#lines+1] = ""
            did = did + 1
        else
            errors[#errors+1] = "HTTP 解析: " .. err
        end
    end

    -- 3) Payload 检测 + 解码
    local hex_data = file_data or tcp_payload
    if hex_data ~= nil and is_hex(hex_data) then
        local res, err = btab_call("POST", "/api/analyze/detect",
            { content = hex_data, input_format = "hex" })
        if res then
            lines[#lines+1] = fmt_detect_result(nil, res)
            did = did + 1
        else
            errors[#errors+1] = "Payload 检测: " .. err
        end
        local dec, derr = btab_call("POST", "/api/analyze/decode",
            { content = hex_data, input_format = "hex" })
        if dec then
            lines[#lines+1] = "===== Payload 解码 ====="
            for _, l in ipairs(fmt_decode_result(dec)) do lines[#lines+1] = l end
            did = did + 1
        else
            errors[#errors+1] = "Payload 解码: " .. derr
        end
    end

    local sid = selected_stream(fields)

    local function finish()
        if #errors > 0 then
            lines[#lines+1] = "[部分分析失败]"
            for _, e in ipairs(errors) do lines[#lines+1] = "  " .. e end
        end
        if did == 0 and sid == nil then
            lines[#lines+1] = "该数据包无可分析内容（非 HTTP 且无 TCP payload）"
        end
        local alert_count = 0
        for _ in pairs(ANN) do alert_count = alert_count + 1 end
        local tw = TextWindow.new(alert_count > 0 and
            ("BTAB 一键分析 [" .. alert_count .. " 帧告警]") or "BTAB 一键分析")
        tw:set(table.concat(lines, "\n"))
        tw:set_editable(false)
        if alert_count > 0 then add_alert_buttons(tw) end
    end

    -- 4) 会话级综合分析（异步：tap 重扫完成后执行）
    if sid ~= nil then
        collect_exchanges("tcp.stream == " .. sid .. " && http", function(ex)
            lines[#lines+1] = "===== 会话综合分析 (tcp.stream " .. sid .. ") ====="
            if #ex > 0 then
                local res, err = btab_call("POST", "/api/analyze/session", { exchanges = ex })
                if res then
                    local count = apply_annotations(res)
                    for _, l in ipairs(report_lines(res, true)) do lines[#lines+1] = l end
                    if count > 0 and not reload_capture() then
                        lines[#lines+1] = "(自动刷新失败，请按 Ctrl+R 重新加载捕获以显示 BTAB 告警树)"
                    end
                else
                    lines[#lines+1] = "调用失败: " .. err
                end
            else
                lines[#lines+1] = "该 TCP 会话中无 HTTP 交互"
            end
            finish()
        end)
    else
        finish()
    end
end

local function menu_clear_alerts()
    ANN = {}
    reload_capture()
end

--==================== Tools 菜单 ====================
local function menu_health()
    local res, err = btab_call("GET", "/api/analyze/health", nil)
    if res == nil then
        show_error("BTAB 服务状态", err ..
            "\n\n请确认：\n  1. btab server 已启动\n  2. API 地址配置正确（Edit->Preferences->Protocols->BTAB）")
        return
    end
    local lines = { "BTAB 服务状态", "", "地址: " .. base_url(),
        "版本: " .. tostring(res.version), "运行: " .. tostring(res.uptime_sec) .. "s",
        "tshark: " .. tostring(res.tshark_path),
        "tshark 可用: " .. tostring(res.tshark_ok), "" }
    if type(res.engines) == "table" then
        lines[#lines+1] = "检测引擎: " .. table.concat(res.engines, ", ")
    end
    if type(res.plugins) == "table" then
        lines[#lines+1] = "插件: " .. table.concat(res.plugins, ", ")
    end
    show_result("BTAB 服务状态", table.concat(lines, "\n"))
end

-- pcap 文件攻击梳理（高级用法：BTAB 服务端本地文件）
local function menu_pcap_dialog()
    local function go(path, filter)
        if path == nil or path == "" then
            show_error("BTAB pcap 分析", "未提供 pcap 文件路径")
            return
        end
        local res, err = btab_call("POST", "/api/analyze/pcap",
            { file = path, filter = (filter ~= "" and filter or "http") })
        if res == nil then show_error("BTAB pcap 分析", err) return end

        local lines = { "BTAB pcap 分析", "", "文件: " .. path }
        if type(res.summary) == "table" then
            lines[#lines+1] = string.format("总流数: %s  命中流数: %s  攻击类型: %s",
                tostring(res.summary.total_flows), tostring(res.summary.detected_flows),
                type(res.summary.attack_types) == "table" and
                    table.concat(res.summary.attack_types, ",") or "-")
        end
        lines[#lines+1] = ""
        if type(res.flows) == "table" then
            for _, f in ipairs(res.flows) do
                local det = ""
                if type(f.detections) == "table" and #f.detections > 0 then
                    local kinds = {}
                    for _, d in ipairs(f.detections) do kinds[#kinds+1] = d.type end
                    det = "  <<< 命中: " .. table.concat(kinds, ",")
                end
                lines[#lines+1] = string.format(
                    "#%s %s:%s -> %s:%s %s %s://%s%s%s",
                    tostring(f.frame), tostring(f.src_ip), tostring(f.src_port),
                    tostring(f.dst_ip), tostring(f.dst_port), tostring(f.method),
                    tostring(f.host ~= "" and f.host or f.dst_ip), tostring(f.uri), det)
                if type(f.detections) == "table" then
                    for _, d in ipairs(f.detections) do
                        lines[#lines+1] = "    [" .. d.type .. "] " .. tostring(d.detail)
                    end
                end
            end
        end
        show_result("BTAB pcap 分析", table.concat(lines, "\n"))
    end
    new_dialog("BTAB pcap 分析 (服务端文件)", go,
        "pcap 文件路径 (BTAB 服务端路径)", "display filter (默认 http)")
end

-- 解码对话框
local function menu_decode_dialog()
    local function go(content, encoding)
        if content == nil or content == "" then return end
        local req = { content = content }
        if encoding ~= nil and encoding ~= "" and encoding ~= "auto" then
            req.encoding = encoding
        end
        if is_hex(content) then req.input_format = "hex" end
        local res, err = btab_call("POST", "/api/analyze/decode", req)
        if res == nil then show_error("BTAB 解码", err) return end
        local lines = { "BTAB 解码", "" }
        if type(res.results) == "table" then
            for _, r in ipairs(res.results) do
                lines[#lines+1] = "===== " .. tostring(r.encoding) ..
                    (r.success and "" or " (失败)") .. " ====="
                lines[#lines+1] = tostring(r.output or r.note or "")
                lines[#lines+1] = ""
            end
        end
        show_result("BTAB 解码", table.concat(lines, "\n"))
    end
    new_dialog("BTAB Payload 解码", go,
        "内容 (原文或 hex)", "编码 auto/base64/base64url/url/hex/java")
end

-- 文本分析对话框：粘贴任意文本/hex，选择分析项执行
-- （Wireshark Lua 无法读取字节窗格中的选中文本，需要手动复制粘贴至此）
local function menu_text_dialog()
    local function go(content, what)
        if content == nil or content == "" then return end
        local fmt = is_hex(content) and "hex" or "raw"
        local w = (what or ""):lower()
        if w == "" or w == "auto" then w = "all" end
        local lines = { "BTAB 文本分析", "", "BTAB: " .. base_url(), "" }
        local did = 0

        if w == "all" or w == "detect" then
            lines[#lines+1] = "===== 攻击检测 ====="
            local res, err = btab_call("POST", "/api/analyze/detect",
                { content = content, url_decode = true, input_format = fmt })
            if res then
                lines[#lines+1] = fmt_detect_result(res, nil)
            else
                lines[#lines+1] = "调用失败: " .. err
            end
            did = did + 1
        end
        if w == "all" or w == "decode" then
            lines[#lines+1] = "===== Payload 解码 ====="
            local res, err = btab_call("POST", "/api/analyze/decode",
                { content = content, input_format = fmt })
            if res then
                for _, l in ipairs(fmt_decode_result(res)) do lines[#lines+1] = l end
            else
                lines[#lines+1] = "调用失败: " .. err
            end
            did = did + 1
        end
        if w == "all" or w == "http_parse" or w == "parse" then
            lines[#lines+1] = "===== HTTP 解析 ====="
            local res, err = btab_call("POST", "/api/analyze/http_parse", { req_data = content })
            if res then
                for _, l in ipairs(fmt_http_parse(res)) do lines[#lines+1] = l end
            else
                lines[#lines+1] = "调用失败: " .. err
            end
            did = did + 1
        end
        if did == 0 then
            lines[#lines+1] = "未知分析项: " .. tostring(what) .. "（可用 all/detect/decode/http_parse）"
        end
        show_result("BTAB 文本分析", table.concat(lines, "\n"))
    end
    new_dialog("BTAB 文本分析", go,
        "内容 (原文或 hex)", "分析项 all/detect/decode/http_parse")
end

-- DSL 引擎查询（DSL 较长，从文件读取）
local function menu_engine_dialog()
    local function go(dsl_file)
        if dsl_file == nil or dsl_file == "" then return end
        local f = io.open(dsl_file, "rb")
        if not f then
            show_error("BTAB DSL 引擎", "无法打开文件: " .. dsl_file)
            return
        end
        local dsl = f:read("*a")
        f:close()
        local res, err = btab_call("POST", "/api/analyze/engine", { query = dsl })
        if res == nil then show_error("BTAB DSL 引擎", err) return end
        show_result("BTAB DSL 引擎结果",
            "DSL 文件: " .. dsl_file .. "\n\n" .. tostring(res.result))
    end
    new_dialog("BTAB DSL 引擎查询", go, "DSL 脚本文件路径 (.btab)")
end

--==================== 注册菜单 ====================
if gui_enabled() then
    register_menu("BTAB/综合分析 (nuclei + 跨会话)", menu_session_analysis, MENU_TOOLS_UNSORTED)
    register_menu("BTAB/清除告警标注", menu_clear_alerts, MENU_TOOLS_UNSORTED)
    register_menu("BTAB/分析当前捕获", menu_analyze_capture, MENU_TOOLS_UNSORTED)
    register_menu("BTAB/服务状态", menu_health, MENU_TOOLS_UNSORTED)
    register_menu("BTAB/文本分析", menu_text_dialog, MENU_TOOLS_UNSORTED)
    register_menu("BTAB/Payload 解码", menu_decode_dialog, MENU_TOOLS_UNSORTED)
    register_menu("BTAB/DSL 引擎查询", menu_engine_dialog, MENU_TOOLS_UNSORTED)
    register_menu("BTAB/pcap 服务端文件", menu_pcap_dialog, MENU_TOOLS_UNSORTED)

    -- Wireshark 4.2+ 数据包右键菜单（按选中粒度分组：帧 / 会话）
    if register_packet_menu ~= nil then
        register_packet_menu("BTAB/一键分析", packet_oneclick, "frame.number")
        register_packet_menu("BTAB/帧/攻击检测", packet_detect, "http or tcp.payload")
        register_packet_menu("BTAB/帧/HTTP 深度解析", packet_http_parse, "http.request")
        register_packet_menu("BTAB/帧/Payload 解码", packet_decode,
            "http.file_data or tcp.payload or data.data")
        register_packet_menu("BTAB/会话/HTTP 流攻击梳理", packet_stream_flows, "tcp.stream")
        register_packet_menu("BTAB/会话/综合分析 (nuclei)", packet_stream_session, "tcp.stream")
    end
end

-- 暴露内部模块便于脚本测试（Wireshark 加载时忽略返回值）
return {
    json = json,
    http_request = http_request,
    btab_call = btab_call,
    base_url = base_url,
    fmt_detect_result = fmt_detect_result,
    fmt_http_parse = fmt_http_parse,
    fmt_decode_result = fmt_decode_result,
    report_lines = report_lines,
    apply_annotations = apply_annotations,
    extract_flow = extract_flow,
    extract_http_row = extract_http_row,
    pair_rows = pair_rows,
}
