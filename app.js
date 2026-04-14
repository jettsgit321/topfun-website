const yearEl = document.getElementById("year");
const form = document.getElementById("leadForm");
const message = document.getElementById("formMessage");
const planSelect = document.getElementById("planSelect");
const planButtons = document.querySelectorAll(".plan-cta[data-plan]");

if (yearEl) {
  yearEl.textContent = String(new Date().getFullYear());
}

for (const button of planButtons) {
  button.addEventListener("click", () => {
    const chosenPlan = button.getAttribute("data-plan");
    if (planSelect && chosenPlan) {
      planSelect.value = chosenPlan;
    }
  });
}

function setMessage(type, text, link) {
  if (!message) {
    return;
  }

  message.textContent = "";
  message.style.color = type === "error" ? "#ff8d99" : "#9bf3b1";

  const textNode = document.createTextNode(text);
  message.appendChild(textNode);

  if (link) {
    message.appendChild(document.createTextNode(" "));
    const anchor = document.createElement("a");
    anchor.href = link;
    anchor.target = "_blank";
    anchor.rel = "noopener noreferrer";
    anchor.textContent = "Open checkout";
    anchor.style.color = "#ffffff";
    anchor.style.fontWeight = "700";
    anchor.style.textDecoration = "underline";
    message.appendChild(anchor);
  }
}

async function createCheckoutLink(payload) {
  const response = await fetch("/api/create-checkout", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok || !data || !data.checkoutUrl) {
    throw new Error((data && data.error) || "Could not create checkout link.");
  }

  return data;
}

if (form && message) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const submitButton = form.querySelector('button[type="submit"]');
    const formData = new FormData(form);
    const username = String(formData.get("username") || "").trim();
    const email = String(formData.get("email") || "").trim();
    const plan = String(formData.get("plan") || "").trim();

    if (!username || !email || !plan) {
      setMessage("error", "Please complete all fields before continuing.");
      return;
    }

    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = "Creating link...";
    }

    try {
      const result = await createCheckoutLink({ username, email, plan });

      if (result.mode === "stripe") {
        setMessage("success", "Redirecting to secure checkout...");
        window.location.href = result.checkoutUrl;
        return;
      }

      setMessage("success", `Test checkout link ready for ${username}.`, result.checkoutUrl);
      form.reset();
    } catch (error) {
      setMessage(
        "error",
        `${error.message} Start with \"node server.js\" to test the full purchase flow.`
      );
    } finally {
      if (submitButton) {
        submitButton.disabled = false;
        submitButton.textContent = "Get Checkout Link";
      }
    }
  });
}
