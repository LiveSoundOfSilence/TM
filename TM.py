import streamlit as st
import yaml
import os

# Default empty structure for a new threat model
DEFAULT_DFD = {"external_entities": [], "processes": [], "data_stores": [], "data_flows": []}

# Load or create the YAML file
def load_dfd():
    """Load DFD data from YAML file or return an empty template if file doesn't exist."""
    if os.path.exists("dfd_template.yaml"):
        with open("dfd_template.yaml", "r") as f:
            return yaml.safe_load(f)
    return DEFAULT_DFD.copy()

# Save the DFD YAML file
def save_dfd(dfd_data):
    """Save DFD data to YAML file."""
    with open("dfd_template.yaml", "w") as f:
        yaml.dump(dfd_data, f)

# Function to reset DFD
def reset_dfd():
    """Reset the DFD to an empty template."""
    save_dfd(DEFAULT_DFD.copy())

# Function to generate a text-based DFD
def generate_text_dfd(dfd_data):
    """Generate a text-based Data Flow Diagram (DFD)."""
    dfd_text = "📜 **Text-Based Data Flow Diagram** 📜\n\n"

    dfd_text += "**🌐 External Entities:**\n"
    if not dfd_data["external_entities"]:
        dfd_text += "- No external entities defined.\n"
    for entity in dfd_data["external_entities"]:
        dfd_text += f"- {entity['name']}: {entity['description']} (STRIDE: {', '.join(entity.get('stride_threats', []))})\n"

    dfd_text += "\n**🖥️ Processes:**\n"
    if not dfd_data["processes"]:
        dfd_text += "- No processes defined.\n"
    for process in dfd_data["processes"]:
        dfd_text += f"- {process['name']}: {process['description']} (STRIDE: {', '.join(process.get('stride_threats', []))})\n"

    dfd_text += "\n**🗄️ Data Stores:**\n"
    if not dfd_data["data_stores"]:
        dfd_text += "- No data stores defined.\n"
    for store in dfd_data["data_stores"]:
        dfd_text += f"- {store['name']}: {store['description']} (STRIDE: {', '.join(store.get('stride_threats', []))})\n"

    dfd_text += "\n**🔀 Data Flows:**\n"
    if not dfd_data["data_flows"]:
        dfd_text += "- No data flows defined.\n"
    for flow in dfd_data["data_flows"]:
        dfd_text += f"- `{flow['from']}` → `{flow['to']}`: {flow['data']} (Risk: {flow['risk_level']}, STRIDE: {', '.join(flow.get('stride_threats', []))})\n"

    return dfd_text

# Function to save the DFD report for GitLab CI/CD
def save_dfd_report(dfd_data):
    """Save the text-based DFD report to a file for GitLab CI/CD integration."""
    report = generate_text_dfd(dfd_data)
    with open("dfd_report.txt", "w") as f:
        f.write(report)

# Initialize Streamlit app
st.title("🛡️ Interactive Threat Modeling Tool")

# Load current DFD data
dfd_data = load_dfd()

# Button to clear all data
if st.button("🗑 Clear Threat Model"):
    reset_dfd()
    st.success("Threat model cleared! Reload the page to start fresh.")
    st.stop()  # Stop execution to ensure old data doesn't persist

# Input for External Entities
st.subheader("🌐 External Entities")
new_entity_name = st.text_input("Add New External Entity Name:", key="entity_name")
new_entity_desc = st.text_area("Description for the Entity:", key="entity_desc")
new_entity_threats = st.multiselect("STRIDE Threats:", 
    ["Spoofing", "Tampering", "Repudiation", "InformationDisclosure", "DenialOfService", "ElevationOfPrivilege"],
    key="entity_threats"
)
if st.button("➕ Add External Entity"):
    if new_entity_name:
        dfd_data["external_entities"].append({"name": new_entity_name, "description": new_entity_desc, "stride_threats": new_entity_threats})
        save_dfd(dfd_data)
        st.success(f"Added {new_entity_name}!")

# Input for Processes
st.subheader("🖥️ Processes")
new_process_name = st.text_input("Add New Process Name:", key="process_name")
new_process_desc = st.text_area("Description for the Process:", key="process_desc")
new_process_threats = st.multiselect("STRIDE Threats:", 
    ["Spoofing", "Tampering", "Repudiation", "InformationDisclosure", "DenialOfService", "ElevationOfPrivilege"],
    key="process_threats"
)
if st.button("➕ Add Process"):
    if new_process_name:
        dfd_data["processes"].append({"name": new_process_name, "description": new_process_desc, "stride_threats": new_process_threats})
        save_dfd(dfd_data)
        st.success(f"Added {new_process_name}!")

# Input for Data Stores
st.subheader("🗄️ Data Stores")
new_store_name = st.text_input("Add New Data Store Name:", key="store_name")
new_store_desc = st.text_area("Description for the Data Store:", key="store_desc")
new_store_threats = st.multiselect("STRIDE Threats:", 
    ["Spoofing", "Tampering", "Repudiation", "InformationDisclosure", "DenialOfService", "ElevationOfPrivilege"],
    key="store_threats"
)
if st.button("➕ Add Data Store"):
    if new_store_name:
        dfd_data["data_stores"].append({"name": new_store_name, "description": new_store_desc, "stride_threats": new_store_threats})
        save_dfd(dfd_data)
        st.success(f"Added {new_store_name}!")

# Input for Data Flows
st.subheader("🔀 Data Flows")
new_flow_from = st.text_input("Data Flow Source (From):", key="flow_from")
new_flow_to = st.text_input("Data Flow Destination (To):", key="flow_to")
new_flow_data = st.text_input("Data Flow Description:", key="flow_data")
new_flow_risk = st.selectbox("Risk Level:", ["high", "medium", "low"], key="flow_risk")
new_flow_threats = st.multiselect("STRIDE Threats:", 
    ["Spoofing", "Tampering", "Repudiation", "InformationDisclosure", "DenialOfService", "ElevationOfPrivilege"],
    key="flow_threats"
)
if st.button("➕ Add Data Flow"):
    if new_flow_from and new_flow_to:
        dfd_data["data_flows"].append({
            "from": new_flow_from, 
            "to": new_flow_to, 
            "data": new_flow_data, 
            "risk_level": new_flow_risk, 
            "stride_threats": new_flow_threats
        })
        save_dfd(dfd_data)
        st.success(f"Added Data Flow from {new_flow_from} to {new_flow_to}!")

# Button to Generate DFD
if st.button("📊 Generate Data Flow Diagram"):
    st.subheader("📜 Generated Data Flow Diagram (Text-Based)")
    dfd_text = generate_text_dfd(dfd_data)
    st.text(dfd_text)
    save_dfd_report(dfd_data)  # Save report for GitLab CI/CD
    st.success("DFD Report saved as 'dfd_report.txt'!")
