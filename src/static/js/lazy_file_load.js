const elt_lazy = document.getElementById("lazy-file-content");

async function lazy_load() {
    const res = await fetch(location, { method: "GET", headers: { "X-Partial": "1" } });
    if (!res.ok) {
        elt_lazy.outerHTML = '<small class="empty_msg">Could not load file contents...</small>';
        return;
    }
    elt_lazy.outerHTML = await res.text();
}

if (elt_lazy) lazy_load();
