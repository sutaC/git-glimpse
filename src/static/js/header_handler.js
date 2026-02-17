/** @type {HTMLElement} */
const elt_header_nav = document.querySelector("header nav");

document.getElementById("menu_toggle").addEventListener("click", (e) => {
    elt_header_nav.classList.add("open");
    document.body.style.overflow = "hidden";
});

document.querySelector("header nav + .backdrop").addEventListener("click", (e) => {
    elt_header_nav.classList.remove("open");
    document.body.style.overflow = "auto";
});
