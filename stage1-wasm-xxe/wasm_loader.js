/**
 * QA CTF — WebAssembly Loader & XML Validator Bridge
 * This module loads the obfuscated Wasm and provides JS interface
 */

const fs = require('fs');
const path = require('path');

class WasmXMLValidator {
  constructor() {
    this.wasm = null;
    this.memory = null;
    this.initialized = false;
  }

  async init() {
    const wasmPath = path.join(__dirname, 'xml_validator.wasm');
    const wasmBuffer = fs.readFileSync(wasmPath);

    // Import object for anti-debug timing
    const importObject = {
      env: {
        performance_now: () => {
          // Return high-res timestamp for timing checks
          const [sec, nsec] = process.hrtime();
          return sec * 1000.0 + nsec / 1000000.0;
        }
      }
    };

    const { instance } = await WebAssembly.instantiate(wasmBuffer, importObject);
    this.wasm = instance.exports;
    this.memory = this.wasm.memory;

    // Initialize the module
    this.wasm.init();

    // Trigger polymorphic decode (assembles XML schema in memory)
    this.wasm.session_cleanup();

    this.initialized = true;
    return this;
  }

  /**
   * Validate an XML tag name against the Wasm's internal schema
   * @param {string} tagName - The tag name to validate
   * @returns {boolean} - Whether the tag is valid
   */
  validateTag(tagName) {
    if (!this.initialized) {
      throw new Error('WasmXMLValidator not initialized');
    }

    const encoder = new TextEncoder();
    const bytes = encoder.encode(tagName);
    const len = bytes.length;

    // Allocate memory in Wasm
    const ptr = this.wasm.heap_alloc(len);
    const memView = new Uint8Array(this.memory.buffer);

    // Write tag bytes to Wasm memory
    for (let i = 0; i < len; i++) {
      memView[ptr + i] = bytes[i];
    }

    // Call validator
    const result = this.wasm.validate_xml_tag(ptr, len);
    return result === 1;
  }

  /**
   * Get the list of valid XML tags (after decryption)
   * This is used internally by the server to know which tags to accept
   * @returns {string[]} - List of valid tag names
   */
  getValidTags() {
    if (!this.initialized) return [];

    const memView = new Uint8Array(this.memory.buffer);
    const tags = [];

    for (let i = 0; i < 5; i++) {
      const tagLenOffset = 0x0900 + i * 8;
      const tagPtrOffset = 0x0904 + i * 8;

      const len = new Int32Array(this.memory.buffer)[tagLenOffset / 4];
      const ptr = new Int32Array(this.memory.buffer)[tagPtrOffset / 4];

      if (len > 0 && len < 20 && ptr >= 0x0800 && ptr < 0x1000) {
        const tagBytes = memView.slice(ptr, ptr + len);
        const decoder = new TextDecoder();
        tags.push(decoder.decode(tagBytes));
      }
    }

    return tags;
  }

  /**
   * Red herring — get_flag function (returns fake flag)
   * Players who find this will waste their time
   */
  getFlag() {
    const ptr = this.wasm.heap_alloc(64);
    const len = this.wasm.get_flag(ptr);
    const memView = new Uint8Array(this.memory.buffer);
    const flagBytes = memView.slice(ptr, ptr + len);
    return new TextDecoder().decode(flagBytes);
  }
}

module.exports = WasmXMLValidator;
