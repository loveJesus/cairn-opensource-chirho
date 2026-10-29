// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//
// Small same-origin htmx subset for demo/generated app pages. It supports the local attributes those
// pages use: hx-post, hx-target, hx-swap="innerHTML", hx-trigger="load", custom body events, and a
// tightly parsed hx-on::after-request event dispatch for refreshing safe lists.

const EVENT_NAME_CHIRHO = "[A-Za-z][A-Za-z0-9_:-]{0,127}";
const AFTER_REQUEST_EVENT_CHIRHO = new RegExp(
  `^document\\.body\\.dispatchEvent\\(\\s*new Event\\(\\s*['"](${EVENT_NAME_CHIRHO})['"]\\s*\\)\\s*\\)$`,
);
const BODY_TRIGGER_CHIRHO = new RegExp(`^(${EVENT_NAME_CHIRHO})\\s+from:body$`);

function targetForChirho(elementChirho) {
  const selectorChirho = elementChirho.getAttribute("hx-target");
  if (!selectorChirho || selectorChirho === "this") return elementChirho;
  return document.querySelector(selectorChirho);
}

function requestBodyForChirho(elementChirho) {
  if (elementChirho instanceof HTMLFormElement) {
    return {
      headersChirho: { "content-type": "application/x-www-form-urlencoded;charset=UTF-8" },
      bodyChirho: new URLSearchParams(new FormData(elementChirho)).toString(),
    };
  }
  return {
    headersChirho: { "content-type": "text/plain;charset=UTF-8" },
    bodyChirho: "",
  };
}

async function postAndSwapChirho(elementChirho) {
  const urlChirho = elementChirho.getAttribute("hx-post");
  if (!urlChirho) return;
  const targetChirho = targetForChirho(elementChirho);
  if (!targetChirho) return;

  const requestChirho = requestBodyForChirho(elementChirho);
  const responseChirho = await fetch(urlChirho, {
    method: "POST",
    headers: requestChirho.headersChirho,
    body: requestChirho.bodyChirho,
  });
  targetChirho.innerHTML = await responseChirho.text();

  for (const eventNameChirho of afterRequestEventsForChirho(elementChirho)) {
    document.body.dispatchEvent(new Event(eventNameChirho));
  }
}

function afterRequestEventsForChirho(elementChirho) {
  const afterRequestChirho = elementChirho.getAttribute("hx-on::after-request") || "";
  const eventsChirho = [];
  for (const statementChirho of afterRequestChirho
    .split(";")
    .map((statementChirho) => statementChirho.trim())
    .filter(Boolean)) {
    const eventChirho = statementChirho.match(AFTER_REQUEST_EVENT_CHIRHO);
    if (!eventChirho) return [];
    eventsChirho.push(eventChirho[1]);
  }
  return eventsChirho;
}

function wireSubmitChirho(elementChirho) {
  if (!(elementChirho instanceof HTMLFormElement)) return;
  elementChirho.addEventListener("submit", (eventChirho) => {
    eventChirho.preventDefault();
    postAndSwapChirho(elementChirho);
  });
}

function wireClickChirho(elementChirho) {
  if (elementChirho instanceof HTMLFormElement) return;
  if (elementChirho.hasAttribute("hx-trigger")) return;
  elementChirho.addEventListener("click", (eventChirho) => {
    eventChirho.preventDefault();
    postAndSwapChirho(elementChirho);
  });
}

function wireTriggerChirho(elementChirho) {
  const triggerChirho = elementChirho.getAttribute("hx-trigger") || "";
  for (const partChirho of triggerChirho.split(",").map((partChirho) => partChirho.trim())) {
    if (partChirho === "load") {
      postAndSwapChirho(elementChirho);
      continue;
    }
    const bodyTriggerChirho = partChirho.match(BODY_TRIGGER_CHIRHO);
    if (bodyTriggerChirho) {
      const eventNameChirho = bodyTriggerChirho[1];
      document.body.addEventListener(eventNameChirho, () => postAndSwapChirho(elementChirho));
    }
  }
}

function bootHtmxLiteChirho() {
  document.querySelectorAll("[hx-post]").forEach((elementChirho) => {
    wireSubmitChirho(elementChirho);
    wireClickChirho(elementChirho);
    wireTriggerChirho(elementChirho);
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootHtmxLiteChirho);
} else {
  bootHtmxLiteChirho();
}
