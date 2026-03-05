const elt_pout = document.getElementById("pager-output");
const elt_pager_prev = document.getElementById("pager-prev");
const elt_pager_next = document.getElementById("pager-next");
const elt_pager_num = document.getElementById("pager-num");
const elt_filters = document.getElementById("pager-filters");

const perform_swap = async (url) => {
    if (!elt_pout) return (location = url); // Defaults to full redirect when #pager-output is missing
    const res = await fetch(url, { method: "GET", headers: { "X-Partial": "1" } });
    if (!res.ok) return (location = url); // Defaults to full redirect on fail
    elt_pout.innerHTML = await res.text();
    const page = Number.parseInt(url.searchParams.get("page", "0")) || 0;
    elt_pager_num.innerText = page;
    history.pushState(null, "", url); // Saves url in query param without reload
    elt_pager_prev.disabled = page <= 0;
    elt_pager_next.disabled = res.headers.get("X-Last") == "1";
};

// Filter
elt_filters?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const values = {};
    e.target.querySelectorAll("input, select").forEach((ch) => {
        if (ch.value) values[ch.name] = ch.value;
    });
    const url = new URL(location);
    url.search = "";
    for (const k in values) url.searchParams.set(k, values[k]);
    perform_swap(url);
});
elt_filters?.addEventListener("reset", async (e) => {
    e.preventDefault();
    e.target.querySelectorAll("input, select").forEach((ch) => (ch.value = ""));
    const url = new URL(location);
    url.search = "";
    perform_swap(url);
});

// Pager
const get_page_change_handler = (pgfn) => {
    return async () => {
        const url = new URL(location);
        let page = Number.parseInt(url.searchParams.get("page", 0)) || 0;
        if (page < 0) page = 0;
        else page = pgfn(page);
        url.searchParams.set("page", page);
        perform_swap(url);
    };
};
elt_pager_prev?.addEventListener(
    "click",
    get_page_change_handler((p) => p - 1),
);
elt_pager_next?.addEventListener(
    "click",
    get_page_change_handler((p) => p + 1),
);
