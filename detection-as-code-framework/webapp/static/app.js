(function () {
  "use strict";

  var prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------------------------
   * Sidebar toggle (mobile)
   * ------------------------------------------------------------------ */
  var toggle = document.getElementById("sidebar-toggle");
  var sidebar = document.getElementById("app-sidebar");

  if (toggle && sidebar) {
    toggle.addEventListener("click", function () {
      var isOpen = sidebar.classList.toggle("open");
      toggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });

    document.addEventListener("click", function (event) {
      if (!sidebar.classList.contains("open")) return;
      if (sidebar.contains(event.target) || toggle.contains(event.target)) return;
      sidebar.classList.remove("open");
      toggle.setAttribute("aria-expanded", "false");
    });

    sidebar.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        sidebar.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      });
    });
  }

  /* ------------------------------------------------------------------
   * Drag-and-drop upload (Rules workspace)
   *
   * The real <input type="file" name="rule_file"> stays the actual
   * source of truth for the form submission - this only adds a nicer
   * drop target on top of it and mirrors dropped files onto it via
   * DataTransfer, so the existing server-side handling is untouched.
   * ------------------------------------------------------------------ */
  var dropzone = document.getElementById("dropzone");
  var fileInput = document.getElementById("rule_file");
  var filenameLabel = document.getElementById("dropzone-filename");

  function showSelectedFile(file) {
    if (!file || !filenameLabel) return;
    filenameLabel.textContent = "Selected: " + file.name;
    filenameLabel.hidden = false;
  }

  if (dropzone && fileInput) {
    fileInput.addEventListener("change", function () {
      if (fileInput.files && fileInput.files[0]) {
        showSelectedFile(fileInput.files[0]);
      }
    });

    ["dragenter", "dragover"].forEach(function (eventName) {
      dropzone.addEventListener(eventName, function (event) {
        event.preventDefault();
        event.stopPropagation();
        dropzone.classList.add("drag-active");
      });
    });

    ["dragleave", "drop"].forEach(function (eventName) {
      dropzone.addEventListener(eventName, function (event) {
        event.preventDefault();
        event.stopPropagation();
        if (eventName === "dragleave" && event.target !== dropzone) return;
        dropzone.classList.remove("drag-active");
      });
    });

    dropzone.addEventListener("drop", function (event) {
      var files = event.dataTransfer && event.dataTransfer.files;
      if (files && files.length > 0) {
        fileInput.files = files;
        showSelectedFile(files[0]);
      }
    });

    dropzone.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        fileInput.click();
      }
    });
  }

  /* ------------------------------------------------------------------
   * Scanning state on submit
   *
   * This reflects a real, in-flight server request (the form still
   * submits normally and the browser navigates on response) - the
   * overlay is shown for genuine network/validation latency, not a
   * fabricated delay.
   * ------------------------------------------------------------------ */
  var uploadForm = document.getElementById("upload-form");
  var validateBtn = document.getElementById("validate-btn");
  var scanOverlay = document.getElementById("scan-overlay");

  if (uploadForm && validateBtn && scanOverlay) {
    uploadForm.addEventListener("submit", function (event) {
      if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        return; // let native "required" validation handle it
      }
      validateBtn.disabled = true;
      validateBtn.textContent = "Validating\u2026";
      scanOverlay.hidden = false;
      if (prefersReducedMotion) {
        scanOverlay.querySelector(".scan-beam").style.display = "none";
      }
    });
  }

  /* ------------------------------------------------------------------
   * Smooth-scroll a freshly rendered result panel into view so the
   * PASS/FAIL transition is visible right after a redirect back from
   * a validation submission.
   * ------------------------------------------------------------------ */
  var resultPanel = document.getElementById("result-panel");
  if (resultPanel && "scrollIntoView" in resultPanel) {
    window.requestAnimationFrame(function () {
      resultPanel.scrollIntoView({
        behavior: prefersReducedMotion ? "auto" : "smooth",
        block: "start",
      });
    });
  }
})();
