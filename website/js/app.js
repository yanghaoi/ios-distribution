(function () {
  "use strict";

  function copyText(text, btn) {
    var done = function () {
      var old = btn.textContent;
      btn.textContent = "已复制";
      btn.classList.add("copy-done");
      setTimeout(function () {
        btn.textContent = old;
        btn.classList.remove("copy-done");
      }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {
        fallback(text, done);
      });
    } else {
      fallback(text, done);
    }
  }

  function fallback(text, done) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) {}
    document.body.removeChild(ta);
    done();
  }

  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("button[data-copy]");
    if (!btn) return;
    var sel = btn.getAttribute("data-copy");
    var node = document.querySelector(sel);
    if (node) copyText(node.textContent.trim(), btn);
  });

  function humanSize(bytes) {
    var units = ["B", "KB", "MB", "GB"];
    var n = bytes;
    var i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n = n / 1024;
      i++;
    }
    return (i === 0 ? n : n.toFixed(2)) + " " + units[i];
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function renderPackages(data) {
    var tbody = document.querySelector("#packages tbody");
    if (!tbody) return;
    var base = data.apt.baseUrl;
    tbody.innerHTML = "";

    data.packages.forEach(function (p) {
      var tr = document.createElement("tr");
      var href = base + p.filename.replace(/^pool\//, "pool/");
      tr.innerHTML =
        "<td>" + esc(p.package) + "</td>" +
        "<td>" + esc(p.version) + "</td>" +
        "<td>" + esc(p.architecture) + "</td>" +
        "<td>" + humanSize(p.size) + "</td>" +
        '<td class="sha" title="' + esc(p.sha256) + '">' + esc(p.sha256.slice(0, 16)) + "…</td>" +
        '<td><a href="' + esc(href) + '">下载</a></td>';
      tbody.appendChild(tr);
    });
  }

  fetch("catalog.json", { cache: "no-store" })
    .then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    })
    .then(renderPackages)
    .catch(function (err) {
      var tbody = document.querySelector("#packages tbody");
      if (!tbody) return;
      var tr = document.createElement("tr");
      tr.innerHTML = '<td colspan="6">catalog.json 加载失败：' + esc(err.message) + "</td>";
      tbody.appendChild(tr);
    });
})();