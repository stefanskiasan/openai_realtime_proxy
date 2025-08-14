export interface WebSocketMessage {
  type: string;
  id?: string;
  timestamp: number;
  version?: string;
  data: any;
}

export interface FunctionCall {
  id?: string;
  callId?: string;
  name: string;
  arguments: any;
  timeout?: number;
}

export interface FunctionResult {
  callId?: string;
  success: boolean;
  result?: any;
  error?: {
    code: string;
    message: string;
  };
}

export interface SessionConfig {
  model?: string;
  voice?: string;
  temperature?: number;
  maxTokens?: number;
  language?: string;
  instructions?: string;
  audioConfig?: AudioConfig;
}

export interface AudioConfig {
  inputFormat?: string;
  outputFormat?: string;
  sampleRate?: number;
  channels?: number;
  echoCancellation?: boolean;
  noiseSuppression?: boolean;
  autoGainControl?: boolean;
}

export interface TranscriptionData {
  text: string;
  isFinal: boolean;
  confidence?: number;
  language?: string;
  speaker?: string;
}

export interface ResponseData {
  text: string;
  delta?: string;
  isComplete: boolean;
  turnId?: string;
  metadata?: any;
}

export interface StatusData {
  state: 'idle' | 'listening' | 'processing' | 'speaking' | 'thinking';
  details?: string;
  progress?: number;
}

export interface ErrorData {
  code: string;
  message: string;
  severity?: 'fatal' | 'error' | 'warning' | 'info';
  context?: any;
  recovery?: {
    retryable: boolean;
    retryAfter?: number;
    fallback?: string;
  };
  stack?: string;
}