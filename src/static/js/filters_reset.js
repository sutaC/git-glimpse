document.querySelectorAll(".filters").forEach((form) =>
    form.addEventListener("reset", (e) => {
        e.preventDefault();
        e.target
            .querySelectorAll("input, select")
            .forEach((ch) => (ch.value = ""));
        e.target.submit();
    }),
);
