const elt_form_cleanup = document.getElementById("form_cleanup");

/**
 * Fetches cleanup status from server.
 * @returns {Promise<void>}
 */
const fetch_status = async () => {
    let next = true;
    try {
        const res = await fetch("/admin/cleanup");
        const stat = await res.json();
        next = stat.running;
    } catch (err) {
        console.error("Error occured while fetching status: ", err);
    } finally {
        if (next) {
            setTimeout(fetch_status, 3000);
        } else {
            location.reload();
        }
    }
};

// --- start ---
if (elt_form_cleanup.getAttribute("data-running") == "True") fetch_status();
