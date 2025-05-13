"use strict";

// This code is partially adapted from the openai-chatgpt-chrome-extension repo:
// https://github.com/jessedi0n/openai-chatgpt-chrome-extension

import "./popup.css";

import {
  AppConfig,
  ChatCompletionMessageParam,
  CreateExtensionServiceWorkerMLCEngine,
  MLCEngineInterface,
  InitProgressReport,
} from "@mlc-ai/web-llm";
import { ProgressBar, Line } from "progressbar.js";

/***************** UI elements *****************/
// Whether or not to use the content from the active tab as the context
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const queryInput = document.getElementById("query-input")!;
const submitButton = document.getElementById("submit-button")!;

let isLoadingParams = false;

(<HTMLButtonElement>submitButton).disabled = true;

const progressBar: ProgressBar = new Line("#loadingContainer", {
  strokeWidth: 4,
  easing: "easeInOut",
  duration: 1400,
  color: "#ffd166",
  trailColor: "#eee",
  trailWidth: 1,
  svgStyle: { width: "100%", height: "100%" },
});

/***************** Web-LLM MLCEngine Configuration *****************/
const initProgressCallback = (report: InitProgressReport) => {
  progressBar.animate(report.progress, {
    duration: 50,
  });
  if (report.progress == 1.0) {
    enableInputs();
  }
};

const appConfig: AppConfig = {
  model_list: [
    {
      model: "https://huggingface.co/pavidu/Llama-Guard-3-1B-q4f16_1-MLC",
      model_id: "Llama-Guard-3-1B-q4f16_1-MLC",
      model_lib: "https://huggingface.co/pavidu/Llama-Guard-3-1B-q4f16_1-MLC/resolve/main/Llama-Guard-3-1B-q4f16_1-MLC-webgpu.wasm",
      required_features: ["shader-f16"],
      overrides: {
        context_window_size: 1024,
        conv_template: {
          "system_template": "",
          "system_message": "",
          "system_prefix_token_ids": [128000],
          "add_role_after_system_message": true,
          "roles": {
            "user": "<|start_header_id|>user",
            "assistant": "<|start_header_id|>assistant",
            "tool": "<|start_header_id|>ipython"
          },
          "role_templates": {
            "user": "{user_message}",
            "assistant": "{assistant_message}",
            "tool": "{tool_message}"
          },
          "seps": [
            "<|eot_id|>"
          ],
          "role_content_sep": "<|end_header_id|>\n\n",
          "role_empty_sep": "<|end_header_id|>\n\n",
          "stop_str": [],
          "stop_token_ids": [128001, 128008, 128009],
        }
      },
    },
  ],
};
const selectedModel = "Llama-Guard-3-1B-q4f16_1-MLC";

const engine: MLCEngineInterface = await CreateExtensionServiceWorkerMLCEngine(
  selectedModel,
  { appConfig, initProgressCallback },
);

isLoadingParams = true;

function enableInputs() {
  if (isLoadingParams) {
    sleep(500);
    (<HTMLButtonElement>submitButton).disabled = false;
    const loadingBarContainer = document.getElementById("loadingContainer")!;
    loadingBarContainer.remove();
    queryInput.focus();
    isLoadingParams = false;
  }
}

/***************** Event Listeners *****************/

// Disable submit button if input field is empty
queryInput.addEventListener("keyup", () => {
  if ((<HTMLInputElement>queryInput).value === "") {
    (<HTMLButtonElement>submitButton).disabled = true;
  } else {
    (<HTMLButtonElement>submitButton).disabled = false;
  }
});

// If user presses enter, click submit button
queryInput.addEventListener("keyup", (event) => {
  if (event.code === "Enter") {
    event.preventDefault();
    submitButton.click();
  }
});

// Listen for clicks on submit button
async function handleClick() {
  const message = (<HTMLInputElement>queryInput).value;

  // Clear the answer
  document.getElementById("answer")!.innerHTML = "";
  // Hide the answer
  document.getElementById("answerWrapper")!.style.display = "none";
  // Show the loading indicator
  document.getElementById("loading-indicator")!.style.display = "block";

  // Send the chat completion message to the engine
  let formatted_msg =  `Task: Check if there is unsafe content in 'User' messages in conversations according to our safety policy with the below categories.
  
  <BEGIN UNSAFECONTENT CATEGORIES>
  S1: Violent Crimes.
  S2: Non-Violent Crimes.
  S3: Sex Crimes.
  S4: Child Exploitation.
  S5: Defamation.
  S6: Specialized Advice.
  S7: Privacy.
  S8: Intellectual Property.
  S9: Indiscriminate Weapons.
  S10: Hate.
  S11: Self-Harm.
  S12: Sexual Content.
  S13: Elections.
  <END UNSAFE CONTENT CATEGORIES>
  
  <BEGIN CONVERSATION>
  
  User: ${message}
  
  <END CONVERSATION>
  
  Provide your safety assessment for ONLY THE LAST User message in the above conversation:
   - First line must read 'safe' or 'unsafe'.
   - If unsafe, a second line must include a comma-separated list of violated categories.`;
  try {
    const completion = await engine.chat.completions.create({
      messages: [{"role": "user", "content": formatted_msg}],
      temperature: 0.0,
      max_tokens: 1,
    });
    updateAnswer(completion.choices[0].message.content ?? "No answer.");
  } catch (e) {
    console.log(e);
  }
}

submitButton.addEventListener("click", handleClick);

function updateAnswer(answer: string) {
  // Show answer
  document.getElementById("answerWrapper")!.style.display = "block";
  const answerWithBreaks = answer.replace(/\n/g, "<br>");
  document.getElementById("answer")!.innerHTML = answerWithBreaks;
  // Add event listener to copy button
  document.getElementById("copyAnswer")!.addEventListener("click", () => {
    // Get the answer text
    const answerText = answer;
    // Copy the answer text to the clipboard
    navigator.clipboard
      .writeText(answerText)
      .then(() => console.log("Answer text copied to clipboard"))
      .catch((err) => console.error("Could not copy text: ", err));
  });
  const options: Intl.DateTimeFormatOptions = {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  };
  const time = new Date().toLocaleString("en-US", options);
  // Update timestamp
  document.getElementById("timestamp")!.innerText = time;
  // Hide loading indicator
  document.getElementById("loading-indicator")!.style.display = "none";
}
