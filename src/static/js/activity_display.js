// Filter reset
document.querySelectorAll(".filters").forEach((form) =>
    form.addEventListener("reset", (e) => {
        e.preventDefault();
        e.target
            .querySelectorAll("input, select")
            .forEach((ch) => (ch.value = ""));
        e.target.submit();
    }),
);
// Pager
document.getElementById("pager-prev")?.addEventListener("click", (e) => {
    const params = new URLSearchParams(location.search);
    const page = Number.parseInt(params.get("page", 0)) || 0;
    if (page <= 0) return;
    params.set("page", page - 1);
    location.search = params;
});
document.getElementById("pager-next")?.addEventListener("click", (e) => {
    const params = new URLSearchParams(location.search);
    const page = Number.parseInt(params.get("page", 0)) || 0;
    params.set("page", page + 1);
    location.search = params;
});
