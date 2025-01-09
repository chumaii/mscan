SCAN_DICTS = {
        "sqli": {
            "name": "SQL",
            "fullName": "Structured Query Language Injection (SQLi)",
            "art":r"""                                                       
 ____   ___  _     _   ____                                  
/ ___| / _ \| |   (_) / ___|  ___ __ _ _ __  _ __   ___ _ __ 
\___ \| | | | |   | | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ___) | |_| | |___| |  ___) | (_| (_| | | | | | | |  __/ |   
|____/ \__\_\_____|_| |____/ \___\__,_|_| |_|_| |_|\___|_|       

                    """,
            "recommendation": """
                Escaping All User-Supplied Input <br/>
                Prepared Statements (with Parameterized Queries)<br/>
                Stored Procedures<br/>
                Allow-list Input Validation (White-list)
            """,
        },
        "xss": {
            "name": "XSS",
            "fullName": "Cross-site Scripting (XSS)",
            "art": r"""
__  ______ ____    ____                                  
\ \/ / ___/ ___|  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 \  /\___ \___ \  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 /  \ ___) |__) |  ___) | (_| (_| | | | | | | |  __/ |   
/_/\_\____/____/  |____/ \___\__,_|_| |_|_| |_|\___|_|   
                """,
            "recommendation": """
                Output Encoding and HTML Sanitization<br/>
                Framework Security Protections: React, Angular, ...<br/>
                Configuration header security: Content Security Policy, ...
            """,
        },
        "pt": {
            "name": "Path Traversal",
            "fullName": "Path Traversal",
            "art": r"""
 ____       _   _       _____                                   _ 
|  _ \ __ _| |_| |__   |_   _| __ __ ___   _____ _ __ ___  __ _| |
| |_) / _` | __| '_ \    | || '__/ _` \ \ / / _ \ '__/ __|/ _` | |
|  __/ (_| | |_| | | |   | || | | (_| |\ V /  __/ |  \__ \ (_| | |
|_|   \__,_|\__|_| |_|   |_||_|  \__,_| \_/ \___|_|  |___/\__,_|_|    
                                                        
                                                  
            """,
            "recommendation": """
                Avoid passing user-supplied input to filesystem<br/>
                Validate the user input before processing it
            """,
        },
        "lfi": {
            "name": "LFI",
            "fullName": "Local File Inclusion (LFI)",
            "art": r"""
 _     _____ ___   ____                                  
| |   |  ___|_ _| / ___|  ___ __ _ _ __  _ __   ___ _ __ 
| |   | |_   | |  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |___|  _|  | |   ___) | (_| (_| | | | | | | |  __/ |   
|_____|_|   |___| |____/ \___\__,_|_| |_|_| |_|\___|_|      
                                                        
                                                  
            """,
            "recommendation": """
                Avoid passing user-submitted input to any filesystem<br/>
                Maintain an allow list of files, that may be included by the page, and then use an identifier (for example the index number) to access to the selected file.
            """,
        },
    }