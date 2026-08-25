from fastapi import HTTPException, status

class TaintlaceAPIException(HTTPException):
    def __init__(self, code: str, message: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(
            status_code=status_code,
            detail={
                "success": False,
                "error": {
                    "code": code,
                    "message": message
                }
            }
        )

class ScanNotFoundException(TaintlaceAPIException):
    def __init__(self, scan_id: str):
        super().__init__(
            code="SCAN_NOT_FOUND",
            message=f"Scan with ID '{scan_id}' does not exist.",
            status_code=status.HTTP_404_NOT_FOUND
        )

class FindingNotFoundException(TaintlaceAPIException):
    def __init__(self, fingerprint: str):
        super().__init__(
            code="FINDING_NOT_FOUND",
            message=f"Finding with fingerprint '{fingerprint}' does not exist.",
            status_code=status.HTTP_404_NOT_FOUND
        )

class InvalidInputException(TaintlaceAPIException):
    def __init__(self, message: str):
        super().__init__(
            code="INVALID_INPUT",
            message=message,
            status_code=status.HTTP_400_BAD_REQUEST
        )
