const fs = require('fs');
const path = require('path');
const glob = require('glob');

const htmlFiles = glob.sync('**/*.html', { ignore: 'node_modules/**' });
let hasErrors = false;

htmlFiles.forEach(file => {
  const dir = path.dirname(file);
  const content = fs.readFileSync(file, 'utf8');

  // Match relative src and href values (skip http/https/mailto/#)
  const refs = [...content.matchAll(/(?:src|href)=["'](?!https?:|mailto:|#)([^"']+)["']/g)];

  refs.forEach(match => {
    const ref = match[1].split('?')[0].split('#')[0];
    const resolved = path.join(dir, ref);

    if (!fs.existsSync(resolved)) {
      console.error(`BROKEN: ${file} references "${ref}" — file not found at ${resolved}`);
      hasErrors = true;
    } else {
      console.log(`OK: ${file} -> ${ref}`);
    }
  });
});

if (hasErrors) {
  console.error('\nLink check failed.');
  process.exit(1);
}

console.log(`\nAll links valid across ${htmlFiles.length} HTML file(s).`);