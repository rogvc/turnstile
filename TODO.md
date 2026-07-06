for i in $(seq 1 12); do swift test 2>&1 | grep -E "Test run with|signal|exited with unexpected" | sed "s/^/run $i: /"; done
---
   CLI=/Users/rogvc/projects/github.com/rogvc/nooksworth-cli/Sources/Commands
   for f in Account/AccountGet Account/AccountSetLastKnown Asset/AssetAdd Budget/BudgetPrefSet Budget/BudgetRecommend Budget/BudgetSetMonthly Folder/FolderAdd Folder/FolderSync Goal/GoalAdd Goal/GoalTag Holding/HoldingAdd Holding/HoldingUpdate Merchant/MerchantDelete Merchant/MerchantUpsert NetWorth/NetWorthCurrent Recurring/RecurringCreateFromTx Settings/SettingsSet Tag/TagAttach Tag/TagCreate Tag/TagDelete Tag/TagReallocate Tag/TagReport Transaction/TransactionAdd Transaction/TransactionDelete Transaction/TransactionGet Transaction/TransactionList Transaction/TransactionSplit; do
     echo "=== $f ==="
     wc -l "$CLI/$f.swift"
   done
   Run shell command

 Hook PreToolUse:Bash requires confirmation for this command:
 ask: unknown-command: CLI=/Users/rogvc/projects/github.com/rogvc/nooksworth-cli/Sources/Commands [settings]
 settings.json to update hooks

---

   XCRESULT="/Users/rogvc/Library/Developer/Xcode/DerivedData/Nooksworth-afkyengqoxkmesdldakwptlgurve/Logs/Test/Test-Nooksworth-2026.07.04_17-50-02--0600.xcresult"
   xcrun xcresulttool get test-results summary --path "$XCRESULT" 2>&1 | head -20
   Get summary from original xcresult

 Hook PreToolUse:Bash requires confirmation for this command:
 ask: unknown-command: XCRESULT="/Users/rogvc/Library/Developer/Xcode/DerivedData/Nooksworth-afkyengqoxkmesdldakwptlgurve/Logs/Test/Test-Nooksworth-2026.07.04_17-50-02--0600.xcresult" [settings]
 settings.json to update hooks

---

