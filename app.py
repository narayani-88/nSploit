from flask import Flask, render_template, request, jsonify
import json
import re
from modules_database import MODULES_DB

app = Flask(__name__)

class MetasploitOrganizer:
    def __init__(self):
        self.modules = MODULES_DB
    
    def search_modules(self, query="", category="", target_type=""):
        """Search modules based on query, category, and target type"""
        results = []
        
        for module in self.modules:
            # Filter by category if specified
            if category and module['category'].lower() != category.lower():
                continue
            
            # Filter by target type if specified
            if target_type and target_type.lower() not in [t.lower() for t in module['targets']]:
                continue
            
            # Search in name, description, and tags
            if query:
                search_text = f"{module['name']} {module['description']} {' '.join(module['tags'])}".lower()
                if query.lower() not in search_text:
                    continue
            
            results.append(module)
        
        return results
    
    def get_categories(self):
        """Get all available categories"""
        categories = set()
        for module in self.modules:
            categories.add(module['category'])
        return sorted(list(categories))
    
    def get_targets(self):
        """Get all available target types"""
        targets = set()
        for module in self.modules:
            targets.update(module['targets'])
        return sorted(list(targets))

organizer = MetasploitOrganizer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/search')
def search():
    query = request.args.get('query', '')
    category = request.args.get('category', '')
    target_type = request.args.get('target', '')
    
    results = organizer.search_modules(query, category, target_type)
    return jsonify(results)

@app.route('/api/categories')
def get_categories():
    return jsonify(organizer.get_categories())

@app.route('/api/targets')
def get_targets():
    return jsonify(organizer.get_targets())

@app.route('/api/module/<path:module_path>')
def get_module_details(module_path):
    for module in organizer.modules:
        if module['path'] == module_path:
            return jsonify(module)
    return jsonify({'error': 'Module not found'}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
