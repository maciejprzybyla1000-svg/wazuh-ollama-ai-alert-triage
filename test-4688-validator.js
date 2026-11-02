const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const start = script.indexOf('function get(obj,path)');
const end = script.indexOf('function renderAI(', start);
const context = {};
vm.createContext(context);
vm.runInContext(script.slice(start, end), context);

const mmcAlert = {
  timestamp: '2026-11-02T18:17:51.218+0000',
  data: { win: { system: { eventID: '4688', threadID: '32' }, eventdata: {
    newProcessName: 'C:\\Windows\\System32\\mmc.exe',
    parentProcessName: 'C:\\Windows\\explorer.exe',
    targetUserName: 'Admin', targetDomainName: 'LAB-WIN10', targetUserSid: 'S-1-5-21-111111111-222222222-333333333-1001',
    tokenElevationType: '%%1937', mandatoryLabel: 'S-1-16-12288', commandLine: '',
    newProcessId: '0x1160', processId: '0x1680'
  } } }
};
const mmcAnalysis = {
  severity: 'low',
  summary: 'Zdarzenie 4688 zarejestrowało utworzenie nowego procesu mmc.exe, który został uruchomiony przez explorer.exe na konto Admin.',
  checks: ['Sprawdź, czy użytkownik oczekiwał na utworzenie procesu mmc.exe w tym czasie.', 'Sprawdź, czy nowy proces i proces twórcy są związane z bliskimi zdarzeniami 4688.']
};
const mmcResult = context.validateAnalysis(mmcAlert, mmcAnalysis);
assert.strictEqual(mmcResult.warnings.length, 0, 'zgodna analiza mmc.exe powinna przejść bez ostrzeżenia');

const searchAlert = {
  timestamp: '2026-11-02T18:34:32.274+0000',
  data: { win: { system: { eventID: '4688', threadID: '1936' }, eventdata: {
    newProcessName: 'C:\\Windows\\System32\\SearchFilterHost.exe',
    parentProcessName: 'C:\\Windows\\System32\\SearchIndexer.exe',
    targetUserName: '-', targetUserSid: 'S-1-0-0', subjectUserName: 'LAB-WIN10$',
    tokenElevationType: '%%1936', mandatoryLabel: 'S-1-16-8192', commandLine: '',
    newProcessId: '0x710', processId: '0xd28'
  } } }
};
const searchAnalysis = {
  severity: 'low',
  summary: 'Zdarzenie 4688 zarejestrowało utworzenie SearchFilterHost.exe przez SearchIndexer.exe na koncie Lab-Win10$.',
  checks: [
    'Sprawdź, czy użytkownik oczekiwał utworzenie procesu w tym czasie.',
    'Sprawdź, czy SearchFilterHost.exe i SearchIndexer.exe są powiązane z alertem.',
    'Sprawdź, czy SearchFilterHost.exe jest standardowy, a SearchIndexer.exe jest explorer.exe.',
    'Sprawdź, czy token elevation type 2 i mandatoryLabel S-1-16-8192 są obecne.'
  ]
};
const searchResult = context.validateAnalysis(searchAlert, searchAnalysis);
assert(searchResult.warnings.length >= 3, 'błędna analiza SearchFilterHost.exe powinna zgłosić rozbieżności');
assert(searchResult.warnings.some(w => w.includes('typ tokenu')), 'powinien zostać wykryty błędny typ tokenu');
assert(searchResult.warnings.some(w => w.includes('konto procesu')), 'powinno zostać wykryte niepotwierdzone konto docelowe');
assert(searchResult.analysis.summary.includes('konto docelowe nie zostało podane'), 'skorygowane podsumowanie powinno wskazać brak konta docelowego');
assert(/typ 1/i.test(searchResult.analysis.summary), '%%1936 powinno być opisane jako typ 1');
assert(searchResult.analysis.summary.includes('średni poziom integralności'), 'S-1-16-8192 powinno być opisane jako średnia integralność');
assert.strictEqual(searchResult.analysis.checks.length, 2, 'skorygowany wynik powinien zawierać dokładnie dwie kontrole');

console.log('OK: mmc.exe — brak konfliktu; SearchFilterHost.exe — konflikty wykryte i skorygowane.');
