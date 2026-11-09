# ImageGuard — Digital Forensics Tool for Image Analysis

ImageGuard is a Python-based digital forensics application developed to analyze digital images and extract useful forensic information. It provides image metadata inspection, SHA-256 hash generation, image format validation, and forensic report generation through an interactive Streamlit interface.

## Features

- **Image Upload and Preview:** Upload and preview digital images.
- **Image Information:** View filename, file size, image dimensions, and format.
- **EXIF Metadata Extraction:** Extract available metadata, such as camera details and GPS information.
- **SHA-256 Hashing:** Generate a unique SHA-256 hash for an uploaded image.
- **Image Format Validation:** Compare the file extension with the detected image format.
- **Image Decoding Check:** Check whether the image can be opened and decoded.
- **Hash Registration and Verification:** Register an image hash and compare it later to identify changes.
- **Forensic Report Generation:** Generate downloadable forensic analysis reports.

## Technologies Used

- Python 3.10
- Streamlit
- Pillow (PIL)
- ExifRead
- hashlib
- ReportLab

## Project Structure

```text
ImageGuard/
│
├── app.py
├── forensic_utils.py
├── requirements.txt
├── README.md
├── reports/
└── evidence/
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/ImageGuard.git
```

### 2. Navigate to the project directory

```bash
cd ImageGuard
```

### 3. Install the required dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the application

```bash
python -m streamlit run app.py
```

### 5. Open in your browser

```text
http://localhost:8501
```

## How to Use

1. Launch the ImageGuard application.
2. Upload a digital image.
3. View its preview and file information.
4. Inspect the available EXIF metadata.
5. Generate and examine its SHA-256 hash.
6. Perform image format and decoding checks.
7. Register or verify the image hash using the available functionality.
8. Generate and download the forensic report.

## Applications

- Digital image forensic analysis
- Image metadata inspection
- File integrity checking
- Basic image validation
- Educational cybersecurity and digital forensics demonstrations

## Limitations

- EXIF metadata may be missing or removed from an image.
- A matching SHA-256 hash confirms that the file matches the recorded baseline; it does not prove that the image is authentic.
- A different hash indicates that the file bytes differ from the registered version, but does not identify what changed.
- The local hash registry is not a tamper-proof evidence database.
- ImageGuard is an educational forensic analysis tool and should not be treated as a replacement for professional forensic investigation.

## Academic Project

Developed as a Semester VII Computer Engineering mini-project for the subject **Cyber Security and Digital Forensics (CSDF)**.

## Author

**Gauri Jadhav**

GitHub: [Gauri12005](https://github.com/Gauri12005)

---

**ImageGuard — Analyze. Verify. Preserve.**