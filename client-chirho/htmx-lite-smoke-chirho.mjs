// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//
// Deterministic Node smoke for htmx-lite-chirho.js. It stubs just enough DOM/FormData/fetch
// behavior to prove the helper posts and swaps contact and generated-app surfaces without eval.

function assertChirho(conditionChirho, messageChirho) {
  if (!conditionChirho) throw new Error(messageChirho);
}

async function settleChirho() {
  await Promise.resolve();
  await new Promise((resolveChirho) => setTimeout(resolveChirho, 0));
  await Promise.resolve();
}

async function waitForChirho(predicateChirho, messageChirho) {
  for (let attemptChirho = 0; attemptChirho < 500; attemptChirho += 1) {
    await settleChirho();
    await new Promise((resolveChirho) => setTimeout(resolveChirho, 10));
    if (predicateChirho()) return;
  }
  throw new Error(messageChirho);
}

function assertNoPiiChirho(textChirho, labelChirho, needlesChirho = []) {
  for (const needleChirho of [
    "Alice",
    "alice@example.com",
    "bakery",
    "Generated Secret",
    "generated@example.com",
    ...needlesChirho,
  ]) {
    assertChirho(!textChirho.includes(needleChirho), `${labelChirho} leaked ${needleChirho}`);
  }
}

function countUrlChirho(callsChirho, urlChirho) {
  return callsChirho.filter((callChirho) => callChirho.urlChirho === urlChirho).length;
}

class FakeElementChirho {
  constructor(attributesChirho = {}) {
    this.attributesChirho = attributesChirho;
    this.listenersChirho = {};
    this.innerHTML = "";
  }

  getAttribute(nameChirho) {
    return this.attributesChirho[nameChirho] ?? null;
  }

  hasAttribute(nameChirho) {
    return Object.prototype.hasOwnProperty.call(this.attributesChirho, nameChirho);
  }

  addEventListener(nameChirho, callbackChirho) {
    (this.listenersChirho[nameChirho] ??= []).push(callbackChirho);
  }

  dispatchEvent(eventChirho) {
    for (const callbackChirho of this.listenersChirho[eventChirho.type] ?? []) {
      callbackChirho(eventChirho);
    }
  }

  fireChirho(nameChirho) {
    for (const callbackChirho of this.listenersChirho[nameChirho] ?? []) {
      callbackChirho({ preventDefault() {} });
    }
  }
}

class HTMLFormElementChirho extends FakeElementChirho {}

globalThis.HTMLFormElement = HTMLFormElementChirho;
globalThis.Event = class {
  constructor(typeChirho) {
    this.type = typeChirho;
  }
};
globalThis.FormData = class {
  constructor(formChirho) {
    this.entriesChirho = formChirho.fieldsChirho;
  }

  [Symbol.iterator]() {
    return this.entriesChirho[Symbol.iterator]();
  }
};

const baseUrlChirho = process.env.CAIRN_CHIRHO_CONTACT_SMOKE_BASE_URL || "";
const realServerChirho = baseUrlChirho.length > 0;
let completedContactListResponsesChirho = 0;
let fixedContactListRefusalsChirho = 0;
let latestContactListResponseChirho = "";
// The Rust smoke supplies its real typed renderer's exact body, never a duplicated prose copy.
const expectedContactListRefusalsChirho = realServerChirho
  ? JSON.parse(process.env.CAIRN_CONTACT_LIST_REFUSAL_BODIES_CHIRHO ?? "[]")
  : [];
assertChirho(
  !realServerChirho || (Array.isArray(expectedContactListRefusalsChirho) && expectedContactListRefusalsChirho.length > 0 && expectedContactListRefusalsChirho.every(bodyChirho => typeof bodyChirho === "string" && bodyChirho.length > 0)),
  "real contact smoke requires the engine's typed refusal bodies",
);

function contactListAtExpectedBoundaryChirho() {
  if (!realServerChirho) {
    return listChirho.innerHTML.includes('data-contact-list-chirho="ready"');
  }
  return (
    fixedContactListRefusalsChirho >= 1 &&
    completedContactListResponsesChirho === countUrlChirho(callsChirho, "/app-chirho/contact/contact-list") &&
    listChirho.innerHTML === latestContactListResponseChirho
  );
}

const formChirho = new HTMLFormElementChirho({
  "hx-post": "/app-chirho/contact",
  "hx-target": "#contact-result-chirho",
  "hx-swap": "innerHTML",
  "hx-on::after-request": "document.body.dispatchEvent(new Event('contactListRefreshChirho'))",
});
formChirho.fieldsChirho = [
  ["name_chirho", "Alice Example"],
  ["email_chirho", "alice@example.com"],
  ["message_chirho", "Apartment above the bakery"],
];

const resultChirho = new FakeElementChirho();
const listChirho = new FakeElementChirho({
  "hx-post": "/app-chirho/contact/contact-list",
  "hx-trigger": "load, contactListRefreshChirho from:body",
  "hx-target": "this",
  "hx-swap": "innerHTML",
});
const refreshButtonChirho = new FakeElementChirho({
  "hx-post": "/app-chirho/contact/contact-list",
  "hx-target": "#contact-list-chirho",
  "hx-swap": "innerHTML",
});

const generatedFormChirho = new HTMLFormElementChirho({
  "hx-post": "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho",
  "hx-target": "#generated-private-intake-result-chirho",
  "hx-swap": "innerHTML",
  "hx-on::after-request":
    "document.body.dispatchEvent(new Event('generatedPrivateIntakeListRefreshChirho'))",
});
generatedFormChirho.fieldsChirho = [
  ["business_name_chirho", "Generated Secret Studio"],
  ["email_chirho", "generated@example.com"],
  ["notes_chirho", "Generated Secret request"],
];
const generatedResultChirho = new FakeElementChirho();
const generatedListChirho = new FakeElementChirho({
  "hx-post": "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho/intake-list",
  "hx-trigger": "load, generatedPrivateIntakeListRefreshChirho from:body",
  "hx-target": "this",
  "hx-swap": "innerHTML",
});
const generatedRefreshButtonChirho = new FakeElementChirho({
  "hx-post": "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho/intake-list",
  "hx-target": "#generated-private-intake-list-chirho",
  "hx-swap": "innerHTML",
});
const maliciousResultChirho = new FakeElementChirho();
const maliciousFormChirho = new HTMLFormElementChirho({
  "hx-post": "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho",
  "hx-target": "#generated-malicious-result-chirho",
  "hx-swap": "innerHTML",
  "hx-on::after-request":
    "window.evilChirho = true; document.body.dispatchEvent(new Event('generatedPrivateIntakeListRefreshChirho'))",
});
maliciousFormChirho.fieldsChirho = [["notes_chirho", "Generated Secret malicious"]];

const bodyChirho = new FakeElementChirho();

globalThis.document = {
  readyState: "complete",
  body: bodyChirho,
  querySelectorAll(selectorChirho) {
    assertChirho(selectorChirho === "[hx-post]", "unexpected selector " + selectorChirho);
    return [
      formChirho,
      listChirho,
      refreshButtonChirho,
      ...(realServerChirho
        ? []
        : [
            generatedFormChirho,
            generatedListChirho,
            generatedRefreshButtonChirho,
            maliciousFormChirho,
          ]),
    ];
  },
  querySelector(selectorChirho) {
    if (selectorChirho === "#contact-result-chirho") return resultChirho;
    if (selectorChirho === "#contact-list-chirho") return listChirho;
    if (!realServerChirho && selectorChirho === "#generated-private-intake-result-chirho") {
      return generatedResultChirho;
    }
    if (!realServerChirho && selectorChirho === "#generated-private-intake-list-chirho") {
      return generatedListChirho;
    }
    if (!realServerChirho && selectorChirho === "#generated-malicious-result-chirho") {
      return maliciousResultChirho;
    }
    throw new Error("unexpected querySelector " + selectorChirho);
  },
  addEventListener() {
    throw new Error("DOMContentLoaded should not be registered when document is complete");
  },
};

const callsChirho = [];
const nativeFetchChirho = globalThis.fetch;
globalThis.fetch = async (urlChirho, requestChirho) => {
  callsChirho.push({
    urlChirho,
    bodyChirho: requestChirho.body,
    contentTypeChirho: requestChirho.headers["content-type"],
  });
  if (realServerChirho) {
    assertChirho(typeof nativeFetchChirho === "function", "real-server smoke requires Node fetch");
    const responseChirho = await nativeFetchChirho(new URL(urlChirho, baseUrlChirho).toString(), {
      method: requestChirho.method,
      headers: requestChirho.headers,
      body: requestChirho.body,
    });
    const textChirho = await responseChirho.text();
    const contactListRequestChirho = urlChirho === "/app-chirho/contact/contact-list";
    if (contactListRequestChirho) {
      const fixedContactListRefusalChirho =
        responseChirho.status === 400 && expectedContactListRefusalsChirho.includes(textChirho);
      assertChirho(
        fixedContactListRefusalChirho,
        `real contact list fetch violated the fixed refusal boundary ${responseChirho.status}: ${textChirho}`,
      );
      fixedContactListRefusalsChirho += 1;
      completedContactListResponsesChirho += 1;
      latestContactListResponseChirho = textChirho;
    } else {
      assertChirho(
        responseChirho.ok,
        `real fetch ${urlChirho} failed ${responseChirho.status}: ${textChirho}`,
      );
    }
    return {
      async text() {
        return textChirho;
      },
    };
  }
  return {
    async text() {
      if (urlChirho === "/app-chirho/contact/contact-list") {
        return "<section data-contact-list-chirho=\"ready\"><pre>safe-list</pre></section>";
      }
      if (urlChirho === "/app-chirho/contact") {
        return "<section data-contact-chirho=\"received\"></section>";
      }
      if (
        urlChirho ===
        "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho/intake-list"
      ) {
        return "<section data-generated-private-intake-list-chirho=\"ready\"><pre>perffection-generated-private-intake-chirho/safe</pre></section>";
      }
      if (
        urlChirho === "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho"
      ) {
        return "<section data-generated-private-intake-chirho=\"received\"></section>";
      }
      throw new Error("unexpected fetch " + urlChirho);
    },
  };
};

await import("./htmx-lite-chirho.js");
await waitForChirho(
  () =>
    countUrlChirho(callsChirho, "/app-chirho/contact/contact-list") === 1 &&
    contactListAtExpectedBoundaryChirho() &&
    (realServerChirho ||
      (countUrlChirho(
        callsChirho,
        "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho/intake-list",
      ) === 1 &&
        generatedListChirho.innerHTML.includes(
          "data-generated-private-intake-list-chirho=\"ready\"",
        ))),
  "load should post and swap safe lists",
);
assertChirho(countUrlChirho(callsChirho, "/app-chirho/contact/contact-list") === 1, "load posts contact list once");
assertNoPiiChirho(listChirho.innerHTML, "initial contact list");
assertChirho(!listChirho.listenersChirho.click, "triggered contact list container should not wire click");
if (!realServerChirho) {
  assertChirho(
    countUrlChirho(
      callsChirho,
      "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho/intake-list",
    ) === 1,
    "load posts generated list once",
  );
  assertNoPiiChirho(generatedListChirho.innerHTML, "initial generated list");
  assertChirho(
    !generatedListChirho.listenersChirho.click,
    "triggered generated list container should not wire click",
  );
}

formChirho.fireChirho("submit");
await waitForChirho(
  () =>
    resultChirho.innerHTML.includes("data-contact-chirho=\"received\"") &&
    countUrlChirho(callsChirho, "/app-chirho/contact/contact-list") === 2 &&
    contactListAtExpectedBoundaryChirho(),
  "submit should swap contact result and refresh list",
);
assertChirho(resultChirho.innerHTML.includes("data-contact-chirho=\"received\""), "submit swaps contact result");
assertNoPiiChirho(resultChirho.innerHTML, "contact submit result");
const formCallChirho = callsChirho.find((callChirho) => callChirho.urlChirho === "/app-chirho/contact");
assertChirho(formCallChirho, "contact form was posted");
assertChirho(
  formCallChirho.contentTypeChirho === "application/x-www-form-urlencoded;charset=UTF-8",
  "contact form content type is urlencoded",
);
assertChirho(formCallChirho.bodyChirho.includes("name_chirho=Alice+Example"), "contact name encoded");
assertChirho(formCallChirho.bodyChirho.includes("email_chirho=alice%40example.com"), "contact email encoded");
assertChirho(
  countUrlChirho(callsChirho, "/app-chirho/contact/contact-list") === 2,
  "after-request refresh posts contact list once",
);
if (realServerChirho) {
  assertChirho(fixedContactListRefusalsChirho >= 1, "real list proves the fixed query refusal");
}
assertNoPiiChirho(listChirho.innerHTML, "refreshed contact list");

refreshButtonChirho.fireChirho("click");
await waitForChirho(
  () =>
    countUrlChirho(callsChirho, "/app-chirho/contact/contact-list") === 3 &&
    contactListAtExpectedBoundaryChirho(),
  "manual contact refresh should post list",
);
assertNoPiiChirho(listChirho.innerHTML, "manual contact refresh list");

if (!realServerChirho) {
  generatedFormChirho.fireChirho("submit");
  await waitForChirho(
    () =>
      generatedResultChirho.innerHTML.includes("data-generated-private-intake-chirho=\"received\"") &&
      countUrlChirho(
        callsChirho,
        "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho/intake-list",
      ) === 2,
    "submit should swap generated result and refresh generated list",
  );
  assertNoPiiChirho(generatedResultChirho.innerHTML, "generated submit result");
  assertNoPiiChirho(generatedListChirho.innerHTML, "generated refreshed list");
  const generatedFormCallChirho = callsChirho.find(
    (callChirho) =>
      callChirho.urlChirho ===
      "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho",
  );
  assertChirho(generatedFormCallChirho, "generated form was posted");
  assertChirho(
    generatedFormCallChirho.bodyChirho.includes("business_name_chirho=Generated+Secret+Studio"),
    "generated business name encoded",
  );
  assertChirho(
    generatedFormCallChirho.bodyChirho.includes("email_chirho=generated%40example.com"),
    "generated email encoded",
  );

  generatedRefreshButtonChirho.fireChirho("click");
  await waitForChirho(
    () =>
      countUrlChirho(
        callsChirho,
        "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho/intake-list",
      ) === 3,
    "manual generated refresh should post list",
  );
  assertNoPiiChirho(generatedListChirho.innerHTML, "manual generated refresh list");

  const generatedListCallsBeforeMaliciousChirho = countUrlChirho(
    callsChirho,
    "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho/intake-list",
  );
  maliciousFormChirho.fireChirho("submit");
  await waitForChirho(
    () => maliciousResultChirho.innerHTML.includes("data-generated-private-intake-chirho=\"received\""),
    "malicious fixture still posts and swaps",
  );
  await settleChirho();
  assertChirho(globalThis.evilChirho === undefined, "hx-on parser must not execute arbitrary code");
  assertChirho(
    countUrlChirho(
      callsChirho,
      "/app-chirho/perffection-generated-app-shell-private-intake-candidate-chirho/intake-list",
    ) === generatedListCallsBeforeMaliciousChirho,
    "hx-on parser must reject valid-looking dispatch inside a larger unsafe string",
  );
}

console.log("htmx-lite-ok");
