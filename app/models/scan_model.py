from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, nullable=False)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="Unknown")
    ssl_status = Column(String, default="Not Checked")
    headers_status = Column(String, default="Not Checked")
    login_status = Column(String, default="Not Checked")
    phishing_status = Column(String, default="Not Checked")
    recon_status = Column(String, default="Not Checked")
    raw_results = Column(Text, nullable=True)
    email_sent_to = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
