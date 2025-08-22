Encrypty: A Parallel File Encryption UtilityEncrypty is a C++ command-line utility designed to encrypt and decrypt files within a directory. This project serves as a practical demonstration of various concurrency models in C++, showcasing sequential, multi-process, and multi-threaded approaches to file processing. It also implements different encryption algorithms to illustrate a range of security levels.✨ FeaturesMultiple Concurrency Models: Implements file processing sequentially, with multiple processes, and with multiple threads.Variety of Encryption Algorithms: Demonstrates both a classical Caesar cipher and the industry-standard AES-256-GCM for robust security.Directory Traversal: Recursively finds and processes all files within a specified directory.Environment-Based Configuration: Securely manages encryption keys and passwords using a .env file.🌿 Branch OverviewThis repository is structured into three main branches, each demonstrating a unique approach to the problem.🌳 main branchConcurrency Model: Sequential ProcessingDescription: This branch processes files one by one. It uses a standard std::queue to line up file tasks and executes them in a single-threaded, synchronous manner. It serves as a baseline for performance comparison.Encryption Algorithm: Basic Caesar Cipher.🚀 multiprocessing branchConcurrency Model: Multi-ProcessingDescription: This branch leverages the power of multiple CPU cores by creating a separate child process for each file using the POSIX fork() system call. Inter-process communication and task queuing are managed using POSIX shared memory (shm_open, mmap) and named semaphores.Encryption Algorithm: Basic Caesar Cipher.⚡ multithreading branchConcurrency Model: Multi-ThreadingDescription: This branch uses a pool of worker threads (std::thread) to process files in parallel. It implements a thread-safe producer-consumer queue using std::mutex and std::condition_variable for efficient task distribution.Encryption Algorithm: AES-256-GCM (via OpenSSL), a modern authenticated encryption cipher providing high security and data integrity.🛠️ Technology StackLanguage: C++17Concurrency APIs:POSIX (fork, shm_open, mmap, sem_open)Standard C++ Threads (std::thread, std::mutex, std::condition_variable)Cryptography:OpenSSL (for AES-256-GCM implementation)Caesar Cipher (for demonstration)Build System: Make⚙️ PrerequisitesA C++ compiler (g++)make build automation toolFor Windows Users: MSYS2 with the openssl and openssl-devel packages installed.pacman -S openssl openssl-devel
🚀 Build and RunClone the repository:git clone https://github.com/your-username/your-repo.git
cd your-repo
Checkout your desired branch:# Example:
git checkout multithreading
Configure the Environment:Create a .env file in the root of the project.For the main and multiprocessing branches, add a numeric key:CRYPTION_KEY=3
For the multithreading branch, add a secure password:CRYPTION_PASSWORD="your-strong-and-secret-password"
Build the project:make
This will create two executables: encrypt_decrypt and cryption.Run the application:The main application processes an entire directory../encrypt_decrypt
The program will then prompt you to enter a directory path and an action (encrypt or decrypt).Example:Enter the directory path: test
Enter the action (encrypt/decrypt): encrypt
📂 Code Structure.
├── src/
│   └── app/
│       ├── encryptDecrypt/  # Contains all encryption/decryption logic
│       ├── fileHandling/    # File I/O and .env parsing utilities
│       └── processes/       # Concurrency models (ProcessManagement, Task)
├── test/                    # Directory for test files
├── .env                     # Environment configuration (you must create this)
├── main.cpp                 # Main entry point for the directory processor
└── Makefile                 # Build script
