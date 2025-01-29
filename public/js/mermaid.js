import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
import elkLayouts from "https://cdn.jsdelivr.net/npm/@mermaid-js/layout-elk@0.1.7/dist/mermaid-layout-elk.esm.min.mjs";

const diagrams = document.querySelectorAll(".mermaid");

// Callback to show Mermaid diagram once it's been processed.
// We hide the raw Mermaid code to stop flash of unstyled content.
const mutationCallback = (mutationsList) => {
    for (const mutation of mutationsList) {
        if (
            mutation.type !== "attributes" ||
            mutation.attributeName !== "data-processed"
        ) {
            return;
        }

        // Check if diagram has been processed.
        if (mutation.target.getAttribute("data-processed") === "true") {
            // Add class to show it.
            mutation.target.classList.add("processed");
        }
    }
};

const observer = new MutationObserver(mutationCallback);

// Observe all Mermaid diagrams
for (const diagram of diagrams) {
    observer.observe(diagram, { attributes: true });
}

// Render mermaid diagrams
mermaid.registerLayoutLoaders(elkLayouts);

// Remove observer on page exit
window.addEventListener("beforeunload", () => {
    observer.disconnect();
});
