import requests
from openai import OpenAI
from flask import Flask, request, jsonify
from flask_cors import CORS # <-- NEW IMPORT
import json
import os


app = Flask(__name__)

CORS(app) 

client = OpenAI(
    # Use 0.0.0.0 for hosting services, or localhost for local testing
    base_url='http://localhost:11434/v1', 
    api_key='ollama',
)

def search_cve_database(keyword: str):
    """
    Searches the NVD API for vulnerabilities matching a keyword.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0" 
    
    print(f"🛡️  Searching NVD for CVEs related to: '{keyword}'...")
    try:
        response = requests.get(base_url, params={"keywordSearch": keyword}) 
        response.raise_for_status() 
        
        nvd_data = response.json()
        
        if nvd_data and nvd_data.get("vulnerabilities"):
            cve_records = [item['cve'] for item in nvd_data['vulnerabilities'] if 'cve' in item]
            return cve_records[:3]
        else:
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"Error fetching NVD data: {e}")
        return None


def format_cve_context(cve_records):
    """
    Formats the raw JSON from the NVD API into a clean string for the LLM.
    """
    if not cve_records:
        return "No relevant CVEs found in the NVD search."
        
    context = ""
    for record in cve_records:
        cve_id = record.get('id', 'N/A')
        description = "No description available."
        cvss_score = "Not available."
        
        # 1. Extract Description
        descriptions = record.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', description)
                break
        
        # 2. Extract CVSS Score
        metrics = record.get('metrics', {})
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            v31_metric = metrics['cvssMetricV31'][0].get('cvssData', {})
            base_score = v31_metric.get('baseScore')
            base_severity = v31_metric.get('baseSeverity')
            if base_score and base_severity:
                 cvss_score = f"{base_score} ({base_severity}) [v3.1]"
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            v30_metric = metrics['cvssMetricV30'][0].get('cvssData', {})
            base_score = v30_metric.get('baseScore')
            base_severity = v30_metric.get('baseSeverity')
            if base_score and base_severity:
                 cvss_score = f"{base_score} ({base_severity}) [v3.0]"
        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            v2_metric = metrics['cvssMetricV2'][0]
            base_score = v2_metric.get('baseScore')
            base_severity = v2_metric.get('baseSeverity')
            if base_score and base_severity:
                 cvss_score = f"{base_score} ({base_severity}) [v2.0]"

        
        context += f"CVE ID: {cve_id}\n"
        context += f"Description: {description}\n"
        context += f"CVSS Score: {cvss_score}\n---\n"
        
    return context

# --- 4. GENERATOR: Ask the LLM to answer based on the data (Unchanged logic) ---
def generate_answer(question, context):
    """
    Generates an answer using the LLM with the provided CVE context.
    Returns generated text and a success status.
    """
    prompt = f"""
    You are a cybersecurity analyst assistant. Based *only* on the following CVE data,
    provide a clear and concise answer to the user's question. If the data does not
    contain the answer, state that explicitly. Structure your answer in easy-to-read paragraphs.

    **CVE Data:**
    {context}

    **User Question:** {question}

    **Answer:**
    """
    
    print(" Generating answer with local LLM...")
    try:
        response = client.chat.completions.create(
            model="mistral:latest",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return response.choices[0].message.content, True
    except Exception as e:
        print(f"LLM Generation Error: {e}")
        return f"Error communicating with LLM. Ensure Ollama is running and the 'mistral:latest' model is pulled. Error: {e}", False

# --- 5. FLASK API ENDPOINT ---
@app.route('/api/analyze', methods=['POST'])
def analyze_cve():
    data = request.get_json()
    keyword = data.get('keyword', '').strip()
    question = data.get('question', '').strip()

    if not keyword or not question:
        return jsonify({
            "success": False, 
            "error": "Both 'keyword' and 'question' are required."
        }), 400

    # 1. Retrieve
    cve_records = search_cve_database(keyword)
    
    # 2. Augment (Format Context)
    cve_context = format_cve_context(cve_records)
    
    # 3. Generate
    final_answer, llm_success = generate_answer(question, cve_context)
    
    # 4. Return results to the frontend
    return jsonify({
        "success": llm_success,
        "keyword": keyword,
        "question": question,
        "cve_context": cve_context,
        "final_answer": final_answer
    })


@app.route('/')
def serve_ui():
    return "Backend running. Please view the 'index.html' file in the preview pane."


if __name__ == '__main__':
    print("\n--- Starting Flask RAG Backend ---")
    print("API available at http://127.0.0.1:5000/api/analyze (CORS enabled)")
    print("Ensure Ollama is running and has 'mistral:latest' pulled.")
    app.run(debug=True, host='0.0.0.0', port=5000)
