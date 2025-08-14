import { EventEmitter } from 'events';
import { AudioConfig } from './types';

export class AudioManager extends EventEmitter {
  private audioContext: AudioContext | null = null;
  private mediaStream: MediaStream | null = null;
  private mediaRecorder: MediaRecorder | null = null;
  private audioProcessor: ScriptProcessorNode | null = null;
  private audioQueue: AudioBuffer[] = [];
  private isRecording: boolean = false;
  private isPlaying: boolean = false;
  private config: AudioConfig;
  private audioElement: HTMLAudioElement | null = null;
  private recordingChunks: Blob[] = [];

  constructor(config?: AudioConfig) {
    super();
    
    this.config = {
      sampleRate: config?.sampleRate || 24000,
      channels: config?.channels || 1,
      echoCancellation: config?.echoCancellation !== false,
      noiseSuppression: config?.noiseSuppression !== false,
      autoGainControl: config?.autoGainControl !== false
    };
  }

  public async initialize(): Promise<void> {
    try {
      // Initialize AudioContext
      const AudioContextClass = (window as any).AudioContext || (window as any).webkitAudioContext;
      this.audioContext = new AudioContextClass({
        sampleRate: this.config.sampleRate
      });

      // Create audio element for playback
      this.audioElement = new Audio();
      this.audioElement.autoplay = true;

      this.emit('initialized');
    } catch (error) {
      this.emit('error', new Error(`Failed to initialize audio: ${error}`));
      throw error;
    }
  }

  public async startRecording(): Promise<void> {
    if (this.isRecording) {
      return;
    }

    try {
      // Request microphone access
      this.mediaStream = await navigator.mediaDevices.getUserMedia({
        audio: {
          channelCount: this.config.channels,
          sampleRate: this.config.sampleRate,
          echoCancellation: this.config.echoCancellation,
          noiseSuppression: this.config.noiseSuppression,
          autoGainControl: this.config.autoGainControl
        }
      });

      if (!this.audioContext) {
        await this.initialize();
      }

      // Setup audio processing
      if (this.audioContext) {
        const source = this.audioContext.createMediaStreamSource(this.mediaStream);
        
        // Create processor for PCM conversion
        const bufferSize = 4096;
        this.audioProcessor = this.audioContext.createScriptProcessor(
          bufferSize,
          this.config.channels,
          this.config.channels
        );

        this.audioProcessor.onaudioprocess = (event) => {
          if (!this.isRecording) return;

          const inputBuffer = event.inputBuffer;
          const pcm16Data = this.convertToPCM16(inputBuffer);
          
          // Emit audio data for streaming
          this.emit('audio', pcm16Data);
        };

        // Connect audio nodes
        source.connect(this.audioProcessor);
        this.audioProcessor.connect(this.audioContext.destination);

        // Also setup MediaRecorder for backup recording
        this.setupMediaRecorder();
      }

      this.isRecording = true;
      this.emit('recording-started');

    } catch (error) {
      this.emit('error', new Error(`Failed to start recording: ${error}`));
      throw error;
    }
  }

  private setupMediaRecorder(): void {
    if (!this.mediaStream) return;

    const mimeType = this.getSupportedMimeType();
    
    this.mediaRecorder = new MediaRecorder(this.mediaStream, {
      mimeType,
      audioBitsPerSecond: 128000
    });

    this.mediaRecorder.ondataavailable = (event) => {
      if (event.data.size > 0) {
        this.recordingChunks.push(event.data);
      }
    };

    this.mediaRecorder.onstop = () => {
      const blob = new Blob(this.recordingChunks, { type: mimeType });
      this.recordingChunks = [];
      this.emit('recording-complete', blob);
    };

    // Start recording in chunks
    this.mediaRecorder.start(100); // 100ms chunks
  }

  private getSupportedMimeType(): string {
    const types = [
      'audio/webm;codecs=opus',
      'audio/ogg;codecs=opus',
      'audio/webm',
      'audio/ogg',
      'audio/mp4'
    ];

    for (const type of types) {
      if (MediaRecorder.isTypeSupported(type)) {
        return type;
      }
    }

    return 'audio/webm'; // Fallback
  }

  public stopRecording(): void {
    if (!this.isRecording) {
      return;
    }

    this.isRecording = false;

    // Stop media recorder
    if (this.mediaRecorder && this.mediaRecorder.state !== 'inactive') {
      this.mediaRecorder.stop();
    }

    // Disconnect audio nodes
    if (this.audioProcessor) {
      this.audioProcessor.disconnect();
      this.audioProcessor = null;
    }

    // Stop media stream
    if (this.mediaStream) {
      this.mediaStream.getTracks().forEach(track => track.stop());
      this.mediaStream = null;
    }

    this.emit('recording-stopped');
  }

  private convertToPCM16(audioBuffer: AudioBuffer): ArrayBuffer {
    const length = audioBuffer.length;
    const channels = audioBuffer.numberOfChannels;
    const sampleRate = audioBuffer.sampleRate;

    // Convert to mono if needed
    let floatData: Float32Array;
    
    if (channels === 1) {
      floatData = audioBuffer.getChannelData(0);
    } else {
      // Mix down to mono
      floatData = new Float32Array(length);
      for (let channel = 0; channel < channels; channel++) {
        const channelData = audioBuffer.getChannelData(channel);
        for (let i = 0; i < length; i++) {
          floatData[i] += channelData[i] / channels;
        }
      }
    }

    // Resample if needed (target is 24kHz)
    const targetSampleRate = 24000;
    let resampledData = floatData;
    
    if (sampleRate !== targetSampleRate) {
      resampledData = this.resample(floatData, sampleRate, targetSampleRate);
    }

    // Convert float32 to PCM16
    const pcm16 = new Int16Array(resampledData.length);
    for (let i = 0; i < resampledData.length; i++) {
      const sample = Math.max(-1, Math.min(1, resampledData[i]));
      pcm16[i] = sample * 0x7FFF;
    }

    return pcm16.buffer;
  }

  private resample(
    data: Float32Array,
    fromSampleRate: number,
    toSampleRate: number
  ): Float32Array {
    const ratio = fromSampleRate / toSampleRate;
    const newLength = Math.round(data.length / ratio);
    const result = new Float32Array(newLength);

    for (let i = 0; i < newLength; i++) {
      const index = i * ratio;
      const indexFloor = Math.floor(index);
      const indexCeil = Math.min(indexFloor + 1, data.length - 1);
      const interpolation = index - indexFloor;
      
      result[i] = data[indexFloor] * (1 - interpolation) + 
                  data[indexCeil] * interpolation;
    }

    return result;
  }

  public async playAudio(audioData: string | ArrayBuffer): Promise<void> {
    try {
      if (!this.audioContext) {
        await this.initialize();
      }

      let pcmData: ArrayBuffer;

      if (typeof audioData === 'string') {
        // Decode base64 to ArrayBuffer
        const binaryString = atob(audioData);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        pcmData = bytes.buffer;
      } else {
        pcmData = audioData;
      }

      // Convert PCM16 to AudioBuffer
      const audioBuffer = await this.pcm16ToAudioBuffer(pcmData);
      
      // Add to queue
      this.audioQueue.push(audioBuffer);
      
      // Start playback if not already playing
      if (!this.isPlaying) {
        this.processAudioQueue();
      }

    } catch (error) {
      this.emit('error', new Error(`Failed to play audio: ${error}`));
    }
  }

  private async pcm16ToAudioBuffer(pcmData: ArrayBuffer): Promise<AudioBuffer> {
    if (!this.audioContext) {
      throw new Error('AudioContext not initialized');
    }

    const pcm16 = new Int16Array(pcmData);
    const float32 = new Float32Array(pcm16.length);

    // Convert PCM16 to Float32
    for (let i = 0; i < pcm16.length; i++) {
      float32[i] = pcm16[i] / 0x7FFF;
    }

    // Create AudioBuffer
    const audioBuffer = this.audioContext.createBuffer(
      1, // mono
      float32.length,
      24000 // sample rate
    );

    audioBuffer.getChannelData(0).set(float32);
    
    return audioBuffer;
  }

  private async processAudioQueue(): Promise<void> {
    if (this.audioQueue.length === 0) {
      this.isPlaying = false;
      this.emit('playback-complete');
      return;
    }

    if (!this.audioContext) {
      return;
    }

    this.isPlaying = true;
    const audioBuffer = this.audioQueue.shift()!;

    // Create buffer source
    const source = this.audioContext.createBufferSource();
    source.buffer = audioBuffer;
    source.connect(this.audioContext.destination);

    // Handle playback completion
    source.onended = () => {
      this.processAudioQueue();
    };

    // Start playback
    source.start(0);
    this.emit('playback-started');
  }

  public stopPlayback(): void {
    this.audioQueue = [];
    this.isPlaying = false;
    
    if (this.audioElement) {
      this.audioElement.pause();
      this.audioElement.src = '';
    }

    this.emit('playback-stopped');
  }

  public pausePlayback(): void {
    if (this.audioElement && !this.audioElement.paused) {
      this.audioElement.pause();
      this.emit('playback-paused');
    }
  }

  public resumePlayback(): void {
    if (this.audioElement && this.audioElement.paused) {
      this.audioElement.play();
      this.emit('playback-resumed');
    }
  }

  public setVolume(volume: number): void {
    const normalizedVolume = Math.max(0, Math.min(1, volume));
    
    if (this.audioElement) {
      this.audioElement.volume = normalizedVolume;
    }

    if (this.audioContext) {
      // You could also implement a GainNode for more control
    }
  }

  public getVolume(): number {
    return this.audioElement?.volume || 1;
  }

  public async getAudioDevices(): Promise<MediaDeviceInfo[]> {
    const devices = await navigator.mediaDevices.enumerateDevices();
    return devices.filter(device => device.kind === 'audioinput');
  }

  public async selectAudioDevice(deviceId: string): Promise<void> {
    if (this.isRecording) {
      this.stopRecording();
    }

    // Update config with new device
    this.config = {
      ...this.config,
      // deviceId will be used in getUserMedia constraints
    };

    // Restart recording with new device if was recording
    if (this.isRecording) {
      await this.startRecording();
    }
  }

  public cleanup(): void {
    this.stopRecording();
    this.stopPlayback();

    if (this.audioContext) {
      this.audioContext.close();
      this.audioContext = null;
    }

    if (this.audioElement) {
      this.audioElement.remove();
      this.audioElement = null;
    }

    this.removeAllListeners();
  }

  public isActive(): boolean {
    return this.isRecording || this.isPlaying;
  }

  public getState(): {
    isRecording: boolean;
    isPlaying: boolean;
    queueLength: number;
  } {
    return {
      isRecording: this.isRecording,
      isPlaying: this.isPlaying,
      queueLength: this.audioQueue.length
    };
  }
}