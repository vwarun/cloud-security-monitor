import streamlit as st
import json
import pandas as pd
import requests
import ipaddress
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh

# ================= CONFIG =================
st.set_page_config(page_title="Cloud Security Monitor", layout="wide")
st_autorefresh(interval=5000, key="refresh")

# ================= UI STYLE =================
st.markdown("""
<style>
.stApp {
    background: radial-gradient(circle at top, #020617, #000000);
    color: white;
}

/* Center everything cleanly */
.block-container {
    padding-top: 2rem;
}

/* Glass cards */
.glass {
    background: rgba(255,255,255,0.05);
    border-radius: 18px;
    padding: 25px;
    margin-bottom: 25px;
    backdrop-filter: blur(12px);
    box-shadow: 0 0 30px rgba(0,255,255,0.08);
}

/* Titles */
h1 {
    text-align: center;
    color: #00ffd5;
    text-shadow: 0 0 20px #00ffd5;
}

h2, h3 {
    color: #00ffd5;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: rgba(255,255,255,0.04);
}

/* Alerts glow */
.stAlert {
    border-radius: 12px;
    box-shadow: 0 0 15px rgba(255,0,0,0.4);
}

/* Buttons */
.stDownloadButton button {
    background-color: #00ffd5;
    color: black;
    border-radius: 10px;
}

</style>
""", unsafe_allow_html=True)

# ================= TITLE =================
st.markdown("<h1>🛡️ Cloud Security Monitor</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center;'>🌍 Real-time Threat Intelligence Dashboard</p>", unsafe_allow_html=True)

# ================= SIDEBAR =================
st.sidebar.title("⚙️ Controls")
threshold = st.sidebar.slider("Alert Threshold", 1, 6, 3)

# ================= LOAD DATA =================
uploaded_file = st.file_uploader("Upload your log file", type=["json"])

if uploaded_file:
    logs = json.load(uploaded_file)
else:
    with open("logs.json") as file:
        logs = json.load(file)

df = pd.DataFrame(logs)
df["time"] = pd.to_datetime(df["time"])

failed_logs = df[df["status"] == "failed"]
success_logs = df[df["status"] == "success"]

# ================= GEO FUNCTIONS =================
def is_private(ip):
    return ipaddress.ip_address(ip).is_private

def get_geo(ip):
    if is_private(ip):
        return None, None
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return res.get("lat"), res.get("lon")
    except:
        return None, None

def get_location_details(ip):
    if is_private(ip):
        return "Private Network"
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return f"{res['country']} - {res['city']} (ISP: {res['isp']})"
    except:
        return "Unknown"

# ================= GLOBE =================
st.markdown('<div class="glass">', unsafe_allow_html=True)
st.subheader("🌍 Global Attack Globe")

arc_data = []

TARGET_LAT = 20
TARGET_LON = 78

for ip in failed_logs["ip"].unique():
    lat, lon = get_geo(ip)
    if lat and lon:
        arc_data.append({
            "startLat": lat,
            "startLng": lon,
            "endLat": TARGET_LAT,
            "endLng": TARGET_LON
        })

components.html(f"""
<!DOCTYPE html>
<html>
<head>
<script src="https://unpkg.com/globe.gl"></script>
<style>
body {{ margin: 0; background: black; }}
#globe {{ width: 100%; height: 500px; }}
</style>
</head>
<body>
<div id="globe"></div>

<script>
const arcsData = {json.dumps(arc_data)};

const globe = Globe()(document.getElementById('globe'))
  .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
  .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
  .arcColor(() => ['#ff0000', '#00ffff'])
  .arcDashLength(0.4)
  .arcDashGap(0.2)
  .arcDashAnimateTime(2000)
  .arcsData(arcsData);

</script>
</body>
</html>
""", height=500)

st.markdown('</div>', unsafe_allow_html=True)

# ================= SUMMARY =================
st.markdown('<div class="glass">', unsafe_allow_html=True)

st.subheader("📊 Security Overview")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Attempts", len(df))
col2.metric("Failed Attempts", len(failed_logs))
col3.metric("Successful Logins", len(success_logs))
col4.metric("Unique IPs", df["ip"].nunique())

risk_score = (len(failed_logs)/len(df))*100 if len(df)>0 else 0
st.progress(int(risk_score))
st.write(f"⚡ Risk Level: {risk_score:.2f}%")

st.markdown('</div>', unsafe_allow_html=True)

# ================= LOG TABLE =================
st.markdown('<div class="glass">', unsafe_allow_html=True)

st.subheader("📄 Logs")

def highlight(row):
    if row["status"] == "failed":
        return ['background-color: #ff4b4b']*len(row)
    elif row["status"] == "success":
        return ['background-color: #4bff88']*len(row)
    return ['']*len(row)

st.dataframe(df.style.apply(highlight, axis=1), use_container_width=True)

st.markdown('</div>', unsafe_allow_html=True)

# ================= GRAPH =================
st.markdown('<div class="glass">', unsafe_allow_html=True)

st.subheader("📊 Attack Distribution")
if not failed_logs.empty:
    st.bar_chart(failed_logs["ip"].value_counts())

st.markdown('</div>', unsafe_allow_html=True)

# ================= TIMELINE =================
st.markdown('<div class="glass">', unsafe_allow_html=True)

st.subheader("⏱️ Attack Timeline")
if not failed_logs.empty:
    timeline = failed_logs.groupby(failed_logs["time"].dt.minute).size()
    st.line_chart(timeline)

st.markdown('</div>', unsafe_allow_html=True)

# ================= LOCATION =================
st.markdown('<div class="glass">', unsafe_allow_html=True)

st.subheader("🌍 Attack Locations")

for ip in failed_logs["ip"].unique():
    st.write(f"🔹 {ip} → {get_location_details(ip)}")

st.markdown('</div>', unsafe_allow_html=True)

# ================= ALERTS =================
st.markdown('<div class="glass">', unsafe_allow_html=True)

st.subheader("🚨 Alerts")

counts = failed_logs["ip"].value_counts()

for ip, count in counts.items():
    if count >= threshold:
        st.error(f"🔴 HIGH RISK: {ip} ({count})")
    elif count == threshold - 1:
        st.warning(f"🟡 MEDIUM RISK: {ip}")

st.markdown('</div>', unsafe_allow_html=True)

# ================= EXPORT =================
st.markdown('<div class="glass">', unsafe_allow_html=True)

st.subheader("📄 Export Report")

report = df.to_csv(index=False).encode("utf-8")

st.download_button("Download Report", report, "security_report.csv")

st.markdown('</div>', unsafe_allow_html=True)


# ================= FOOTER =================
st.markdown("---")

st.markdown("""
<div style='text-align: center; width: 100%;'>
<h2 style='color:#00ffd5; text-shadow:0 0 15px #00ffd5;'>🛡️ Cloud Security Monitor</h2>
<p>Built by <b>Varun Wilfred</b></p>
<p>varunwilfred10@gmail.com</p>
<p>
🔗 <a href='https://github.com/vwarun'>GitHub</a> | 
<a href='https://linkedin.com/in/varunwilfred'>LinkedIn</a>
</p>
</div>
""", unsafe_allow_html=True)
