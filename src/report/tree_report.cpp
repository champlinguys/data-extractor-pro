#include "report/tree_report.h"
#include <algorithm>
#include <cstdio>
#include <ctime>
#include <functional>

namespace de::report {

namespace {

std::string lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string isoDate(int64_t ns) {
    if (ns == 0) return "";
    std::time_t t = static_cast<std::time_t>(ns / 1000000000);
    std::tm tm{};
    if (!gmtime_r(&t, &tm)) return "";
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M", &tm);
    return buf;
}

// Walk the tree depth-first, calling `visit(path, node, depth)`. Directories
// are visited before their contents.
void walk(Filesystem& fs, const FsNode& dir, const std::string& path, size_t depth,
          const Options& opt, Stats& stats,
          const std::function<void(const std::string&, const FsNode&, size_t)>& visit) {
    if (depth > opt.maxDepth) return;
    for (const auto& child : fs.listDir(dir)) {
        std::string childPath = path + "/" + child.name;
        if (child.isDir) {
            ++stats.dirs;
            visit(childPath, child, depth);
            walk(fs, child, childPath, depth + 1, opt, stats, visit);
        } else {
            ++stats.files;
            stats.bytes += child.size;
            if (opt.includeFiles) visit(childPath, child, depth);
        }
        if (opt.progress && ((stats.files + stats.dirs) % 2000 == 0))
            opt.progress(stats.files, stats.dirs);
    }
}

void jsonEscape(const std::string& in, std::ostream& out) {
    for (unsigned char c : in) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out << buf;
                } else {
                    out << static_cast<char>(c);
                }
        }
    }
}

} // namespace

std::vector<Entry> collectTree(Filesystem& fs, const FsNode& root, Stats& stats,
                               const Options& opt) {
    std::vector<Entry> entries;
    std::vector<int> stack; // index of the directory open at each depth
    walk(fs, root, "", 0, opt, stats,
         [&](const std::string&, const FsNode& n, size_t depth) {
             if (stack.size() < depth + 1) stack.resize(depth + 1, -1);
             Entry e;
             e.name = n.name;
             e.parent = depth == 0 ? -1 : stack[depth - 1];
             e.isDir = n.isDir;
             e.size = n.size;
             e.mtime = n.times.mtime;
             entries.push_back(std::move(e));
             if (n.isDir) stack[depth] = static_cast<int>(entries.size()) - 1;
         });
    return entries;
}

std::string entryPath(const std::vector<Entry>& entries, int i) {
    std::vector<const std::string*> parts;
    while (i >= 0 && i < static_cast<int>(entries.size())) {
        parts.push_back(&entries[i].name);
        i = entries[i].parent;
    }
    std::string out;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) out += "/" + **it;
    return out.empty() ? "/" : out;
}

void writeTextTree(const std::vector<Entry>& entries, std::ostream& out) {
    out << "# size        modified          path\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        char buf[32];
        if (e.isDir)
            std::snprintf(buf, sizeof buf, "%12s", "<DIR>");
        else
            std::snprintf(buf, sizeof buf, "%12llu",
                          static_cast<unsigned long long>(e.size));
        std::string date = isoDate(e.mtime);
        out << buf << "  " << (date.empty() ? std::string(16, ' ') : date) << "  "
            << entryPath(entries, static_cast<int>(i)) << "\n";
    }
}

Stats findNames(Filesystem& fs, const FsNode& root,
                const std::vector<std::string>& needles,
                const std::function<void(const std::string&, const FsNode&)>& hit,
                const Options& opt) {
    std::vector<std::string> lowered;
    lowered.reserve(needles.size());
    for (const auto& n : needles) lowered.push_back(lower(n));

    Stats stats;
    walk(fs, root, "", 0, opt, stats,
         [&](const std::string& path, const FsNode& n, size_t) {
             std::string name = lower(n.name);
             for (const auto& needle : lowered)
                 if (name.find(needle) != std::string::npos) {
                     hit(path, n);
                     return;
                 }
         });
    return stats;
}

void writeHtmlTree(const std::vector<Entry>& entries, std::ostream& out,
                   const std::string& title) {
    const std::vector<Entry>& nodes = entries;
    out << R"HTML(<!doctype html><html><head><meta charset="utf-8">
<title>)HTML" << title << R"HTML(</title>
<style>
 body{font:13px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#111;color:#ddd}
 header{position:sticky;top:0;background:#1b1b1b;border-bottom:1px solid #333;padding:10px 14px}
 h1{font-size:15px;margin:0 0 8px}
 #q{width:min(560px,70vw);padding:7px 9px;font-size:14px;background:#222;color:#eee;
    border:1px solid #444;border-radius:4px}
 #meta{color:#888;margin-left:10px;font-size:12px}
 #out{padding:6px 14px 40px}
 .row{display:flex;gap:12px;padding:1px 0;white-space:nowrap}
 .row:hover{background:#1d1d1d}
 .nm{flex:1;overflow:hidden;text-overflow:ellipsis}
 .dir>.nm{color:#7fb8ff;cursor:pointer;font-weight:600}
 .sz,.dt{color:#888;font-variant-numeric:tabular-nums;text-align:right}
 .sz{width:90px}.dt{width:120px}
 .path{color:#888}
 mark{background:#5a4a00;color:#ffd}
 .hint{color:#777;padding:10px 14px}
</style></head><body>
<header>
 <h1>)HTML" << title << R"HTML(</h1>
 <input id="q" placeholder="Search every file and folder (e.g. osage, wet, .NEF) - regular expressions work too" autofocus>
 <span id="meta"></span>
</header>
<div id="out"></div>
<script>
const N=)HTML";

    // name, parent, isDir, size, mtime
    out << "[";
    for (size_t i = 0; i < nodes.size(); ++i) {
        if (i) out << ",\n";
        out << "[\"";
        jsonEscape(nodes[i].name, out);
        out << "\"," << nodes[i].parent << "," << (nodes[i].isDir ? 1 : 0) << ","
            << nodes[i].size << "," << nodes[i].mtime / 1000000000 << "]";
    }
    out << "];\n";

    out << R"JS(
const kids={};
N.forEach((n,i)=>{(kids[n[1]]=kids[n[1]]||[]).push(i)});
function fullPath(i){const p=[];while(i>=0){p.unshift(N[i][0]);i=N[i][1]}return "/"+p.join("/")}
function hsize(b){if(b>=1e12)return (b/1e12).toFixed(2)+" TB";if(b>=1e9)return (b/1e9).toFixed(2)+" GB";
 if(b>=1e6)return (b/1e6).toFixed(1)+" MB";if(b>=1e3)return (b/1e3).toFixed(1)+" kB";return b+" B"}
function hdate(t){if(!t)return "";const d=new Date(t*1000);
 return d.toISOString().slice(0,16).replace("T"," ")}
const out=document.getElementById("out"), meta=document.getElementById("meta");
const open=new Set([-1]);
function row(i,depth,path){
 const n=N[i], d=document.createElement("div");
 d.className="row"+(n[2]?" dir":"");
 const nm=document.createElement("div"); nm.className="nm";
 nm.style.paddingLeft=(depth*18)+"px";
 nm.textContent=(n[2]?(open.has(i)?"▾ ":"▸ "):"   ")+n[0];
 if(path){const s=document.createElement("span");s.className="path";s.textContent="  "+path;nm.appendChild(s)}
 if(n[2])nm.onclick=()=>{open.has(i)?open.delete(i):open.add(i);render()};
 const sz=document.createElement("div"); sz.className="sz"; sz.textContent=n[2]?"":hsize(n[3]);
 const dt=document.createElement("div"); dt.className="dt"; dt.textContent=hdate(n[4]);
 d.append(nm,sz,dt); return d;
}
function renderTree(parent,depth,frag){
 (kids[parent]||[]).sort((a,b)=>(N[b][2]-N[a][2])||N[a][0].localeCompare(N[b][0]))
  .forEach(i=>{frag.appendChild(row(i,depth));
   if(N[i][2]&&open.has(i))renderTree(i,depth+1,frag)});
}
function render(){
 const q=document.getElementById("q").value.trim();
 const frag=document.createDocumentFragment();
 if(!q){renderTree(-1,0,frag); meta.textContent=N.length.toLocaleString()+" objects";}
 else{
  let re; try{re=new RegExp(q,"i")}catch(e){re={test:s=>s.toLowerCase().includes(q.toLowerCase())}}
  let hits=0; const cap=3000;
  for(let i=0;i<N.length&&hits<cap;i++){
   if(re.test(N[i][0])){hits++;
    const parent=N[i][1];
    frag.appendChild(row(i,0,parent<0?"/":fullPath(parent)));}
  }
  let total=0; for(let i=0;i<N.length;i++) if(re.test(N[i][0])) total++;
  meta.textContent=total.toLocaleString()+" match"+(total==1?"":"es")+
   (total>cap?" (showing first "+cap+")":"");
 }
 out.replaceChildren(frag);
}
document.getElementById("q").addEventListener("input",()=>{
 clearTimeout(window._t); window._t=setTimeout(render,120)});
render();
</script></body></html>
)JS";
}

} // namespace de::report
