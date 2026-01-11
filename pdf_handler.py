"""
PDF Upload and Text Extraction Module

This module handles PDF file uploads and extracts text content
for analysis by the threat analyzer pipeline.
"""

import io
from typing import Optional
import PyPDF2
from pdfminer.high_level import extract_text as pdfminer_extract


class PDFHandler:
    """
    Handles PDF file uploads and text extraction.
    """
    
    def __init__(self):
        pass
    
    def extract_text(self, pdf_file) -> Optional[str]:
        """
        Extract text from a PDF file.
        
        Args:
            pdf_file: File-like object (BytesIO) or file path
        
        Returns:
            Extracted text as string, or None if extraction fails
        """
        try:
            # Try PyPDF2 first (faster, good for text-based PDFs)
            try:
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                text_parts = []
                
                for page in pdf_reader.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text_parts.append(page_text)
                
                extracted_text = "\n\n".join(text_parts)
                
                # If PyPDF2 extracted meaningful text, use it
                if extracted_text and len(extracted_text.strip()) > 50:
                    return extracted_text.strip()
            except Exception:
                # PyPDF2 failed, try pdfminer
                pass
            
            # Fallback to pdfminer (slower but better for scanned/image PDFs)
            # Reset file pointer if needed
            if hasattr(pdf_file, 'seek'):
                pdf_file.seek(0)
            
            extracted_text = pdfminer_extract(pdf_file)
            
            if extracted_text and len(extracted_text.strip()) > 0:
                return extracted_text.strip()
            else:
                return None
                
        except Exception as e:
            print(f"Error extracting text from PDF: {e}")
            return None
    
    def extract_text_from_bytes(self, pdf_bytes: bytes) -> Optional[str]:
        """
        Extract text from PDF bytes.
        
        Args:
            pdf_bytes: PDF file content as bytes
        
        Returns:
            Extracted text as string, or None if extraction fails
        """
        pdf_file = io.BytesIO(pdf_bytes)
        return self.extract_text(pdf_file)


if __name__ == "__main__":
    # Test the PDF handler
    handler = PDFHandler()
    print("PDF Handler initialized successfully")

