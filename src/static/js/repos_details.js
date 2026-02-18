const elt_status = document.getElementById("status");
const elt_status_spinner = document.getElementById("status_spinner");
const status_fetch_url = new URL(location);
status_fetch_url.searchParams.append("status", "true");

const fetch_status = async () => {
    elt_status_spinner.classList.remove("hidden");
    try {
        const res = await fetch(status_fetch_url);
        const stat = await res.text();
        elt_status.innerText = stat;
        if (stat != "pending" && stat != "running") location.reload();
    } catch (err) {
        console.error("Error occured while fetching status: ", err);
    }
    setTimeout(fetch_status, 3000);
};

if (elt_status.innerText == "pending" || elt_status.innerText == "running") fetch_status();
