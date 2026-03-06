const elt_lazy = document.getElementById("lazy-file-content");

/**
 * Lazy loads file contents.
 * @returns {void}
 */
async function lazy_load() {
    const url = new URL(location);
    url.searchParams.set("partial", "1");
    const res = await fetch(url);
    if (!res.ok) {
        elt_lazy.outerHTML = '<small class="empty_msg">Could not load file contents...</small>';
        return;
    }
    elt_lazy.outerHTML = await res.text();
}

if (elt_lazy) lazy_load();
