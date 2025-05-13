## Converting Llama Guard to MLC

We'll work with https://huggingface.co/meta-llama/Llama-Guard-3-1B.
The installation instructions can be found at https://llm.mlc.ai/docs/deploy/webllm.html#bring-your-own-model-variant.
Below are the specific commands we used for the conversion.
We'll assume you have downloaded Llama-Guard-3-1B to some folder, where the commands are executed, and have set up the installation environment correctly, particularly the wasm.

```
mlc_llm convert_weight Llama-Guard-3-1B --quantization q4f32_1 -o Llama-Guard-3-1B-q4f32_1-MLC
mlc_llm gen_config Llama-Guard-3-1B --quantization q4f32_1 --conv-template llama-3_1 -o Llama-Guard-3-1B-q4f32_1-MLC
mlc_llm compile Llama-Guard-3-1B-q4f32_1-MLC\mlc-chat-config.json --device webgpu -o Llama-Guard-3-1B-q4f32_1-MLC-webgpu.wasm
```

For the last command (`compile`), you will need to have the `mlc_wasm_runtime.bc` file, which must be compiled accorcding to the instructions above.
You might need to change your directory to where you can find this file before you can execute.
You can replace the `q4f32_1` in all of the commands with another quantization option. The most applicable ones are: `q4f16_1, q4f32_1`.