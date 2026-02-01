/**
 * UploadForm - File upload UI for architecture images and JSON.
 * 
 * Features:
 * - Drag and drop support
 * - File type validation (PNG, JPEG, JSON)
 * - Upload progress indicator
 * - Switch to example selector
 */

import { useState, useCallback, useRef } from 'react';
import type { AnalysisInput } from '../../compiler/types';

interface UploadFormProps {
  onSubmit: (input: AnalysisInput) => void;
  onShowExamples: () => void;
  isLoading: boolean;
}

const ACCEPTED_TYPES = {
  'image/png': ['.png'],
  'image/jpeg': ['.jpg', '.jpeg'],
  'application/json': ['.json'],
};

export default function UploadForm({ onSubmit, onShowExamples, isLoading }: UploadFormProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateFile = (file: File): boolean => {
    const validTypes = Object.keys(ACCEPTED_TYPES);
    if (!validTypes.includes(file.type)) {
      setError('Invalid file type. Please upload PNG, JPEG, or JSON files.');
      return false;
    }
    if (file.size > 10 * 1024 * 1024) {
      setError('File too large. Maximum size is 10MB.');
      return false;
    }
    setError(null);
    return true;
  };

  const handleFile = useCallback((file: File) => {
    if (validateFile(file)) {
      setSelectedFile(file);
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  const handleSubmit = useCallback(() => {
    if (!selectedFile) return;

    const isJson = selectedFile.type === 'application/json';
    
    if (isJson) {
      // Read JSON file content
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const json = JSON.parse(e.target?.result as string);
          onSubmit({ type: 'json', json });
        } catch {
          setError('Invalid JSON file');
        }
      };
      reader.readAsText(selectedFile);
    } else {
      // Submit image file
      onSubmit({ type: 'image', file: selectedFile });
    }
  }, [selectedFile, onSubmit]);

  const handleBrowseClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="max-w-2xl mx-auto p-6">
      {/* Header */}
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">
          Left<span className="text-blue-400">&lt;&lt;</span>Shift
        </h1>
        <p className="text-slate-400">
          Upload your architecture diagram or JSON to analyze security threats
        </p>
      </div>

      {/* Drop zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`
          relative border-2 border-dashed rounded-xl p-12
          transition-all duration-200 cursor-pointer
          ${isDragging 
            ? 'border-blue-400 bg-blue-400/10' 
            : 'border-slate-600 hover:border-slate-500 bg-slate-800/50'
          }
          ${selectedFile ? 'border-emerald-500 bg-emerald-500/10' : ''}
        `}
        onClick={handleBrowseClick}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".png,.jpg,.jpeg,.json"
          onChange={handleFileSelect}
          className="hidden"
        />

        <div className="text-center">
          {selectedFile ? (
            <>
              <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-emerald-500/20 flex items-center justify-center">
                <svg
                  className="w-8 h-8 text-emerald-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M5 13l4 4L19 7"
                  />
                </svg>
              </div>
              <p className="text-lg font-medium text-white mb-1">{selectedFile.name}</p>
              <p className="text-sm text-slate-400">
                {(selectedFile.size / 1024).toFixed(1)} KB • Click to change
              </p>
            </>
          ) : (
            <>
              <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-slate-700 flex items-center justify-center">
                <svg
                  className="w-8 h-8 text-slate-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                  />
                </svg>
              </div>
              <p className="text-lg font-medium text-white mb-1">
                Drop your file here or click to browse
              </p>
              <p className="text-sm text-slate-400">
                Supports PNG, JPEG, or JSON architecture files
              </p>
            </>
          )}
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div className="mt-4 p-3 rounded-lg bg-red-500/20 border border-red-500/50 text-red-400 text-sm">
          {error}
        </div>
      )}

      {/* Actions */}
      <div className="mt-6 flex flex-col gap-4">
        <button
          onClick={handleSubmit}
          disabled={!selectedFile || isLoading}
          className={`
            w-full py-3 px-6 rounded-lg font-medium
            transition-all duration-200
            ${selectedFile && !isLoading
              ? 'bg-blue-500 hover:bg-blue-600 text-white'
              : 'bg-slate-700 text-slate-500 cursor-not-allowed'
            }
          `}
        >
          {isLoading ? (
            <span className="flex items-center justify-center gap-2">
              <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                  fill="none"
                />
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                />
              </svg>
              Analyzing...
            </span>
          ) : (
            'Analyze Architecture'
          )}
        </button>

        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-slate-700" />
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-4 bg-slate-900 text-slate-500">or</span>
          </div>
        </div>

        <button
          onClick={onShowExamples}
          disabled={isLoading}
          className="w-full py-3 px-6 rounded-lg font-medium border border-slate-600 text-slate-300 hover:bg-slate-800 transition-all duration-200"
        >
          Try an Example Architecture
        </button>
      </div>
    </div>
  );
}
