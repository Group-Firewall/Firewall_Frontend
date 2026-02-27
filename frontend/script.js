document
  .getElementById("predictionForm")
  .addEventListener("submit", async function (e) {
    e.preventDefault();

    const submitBtn = document.getElementById("predictBtn");
    const resultContainer = document.getElementById("result");
    const resultContent = document.getElementById("resultContent");
    const errorContainer = document.getElementById("error");
    const errorContent = document.getElementById("errorContent");

    // Resetting the  UI
    submitBtn.disabled = true;
    submitBtn.textContent = "Analyzing...";
    resultContainer.classList.add("hidden");
    errorContainer.classList.add("hidden");

    // The Harvest form data
    const formData = new FormData(e.target);
    const data = {};
    formData.forEach((value, key) => {
      // Converting of numbers
      if (key === "Port" || key === "Payload_Size") {
        data[key] = parseInt(value, 10);
      } else {
        data[key] = value;
      }
    });

    try {
      const response = await fetch("http://localhost:8000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Server Error: ${response.status} ${response.statusText} - ${errorText}`,
        );
      }

      const result = await response.json();

      // Display Result
      let resultHTML = "";
      if (result.is_malicious) {
        resultHTML = `<p class="malicious" style="font-size: 1.5rem; margin-bottom: 1rem;">🚨 Malicious</p>`;
      } else {
        resultHTML = `<p class="safe" style="font-size: 1.5rem; margin-bottom: 1rem;">✅ Normal Traffic</p>`;
      }

      resultHTML += `
            <p><strong>Confidence Score:</strong> ${(result.confidence_score * 100).toFixed(2)}%</p>
            <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #cbd5e1;">
                <p><strong>Analysis Details:</strong></p>
                <ul style="list-style-type: none; padding-left: 0; margin-top: 0.5rem;">
                    <li>Signature Detection: ${result.details.signature_detected ? '<span class="malicious">DETECTED</span>' : '<span class="safe">Clean</span>'}</li>
                    <li>ML Detection: ${result.details.ml_detected ? '<span class="malicious">DETECTED</span>' : '<span class="safe">Clean</span>'}</li>
                    <li>Decision Path: <code>${result.details.decision_path}</code></li>
                </ul>
            </div>
        `;

      resultContent.innerHTML = resultHTML;
      resultContainer.classList.remove("hidden");
    } catch (error) {
      console.error("Error:", error);
      errorContent.textContent = error.message;
      errorContainer.classList.remove("hidden");
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "Analyze Traffic";
    }
  });
