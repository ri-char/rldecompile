#include "clang/AST/ASTConsumer.h"
#include "clang/AST/Mangle.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/Sema/Sema.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Support/FileSystem.h>
#include <optional>
#include <sys/stat.h>
#include <sys/types.h>
#include <nlohmann/json.hpp>

using namespace clang;
using nlohmann::json;

namespace {

class FuncDeclVisitor : public RecursiveASTVisitor<FuncDeclVisitor> {
  raw_ostream &out;
  CompilerInstance &Instance;

public:
  FuncDeclVisitor(raw_ostream &out, CompilerInstance &Instance)
      : out(out), Instance(Instance) {}
  bool VisitFunctionDecl(FunctionDecl *FD) {
    if (isa<RequiresExprBodyDecl>(FD->getDeclContext()))
      return true;
    ASTNameGenerator NG(Instance.getASTContext());
    SourceRange range = FD->getSourceRange();
    json output;
    output["name"] = NG.getName(FD);
    output["filename"] = Instance.getSourceManager().getFilename(range.getBegin());
    output["begin_offset"] = Instance.getSourceManager().getFileOffset(range.getBegin());
    output["end_offset"] = Instance.getSourceManager().getFileOffset(range.getEnd());
    out << output.dump() << "\n";
    return true;
  }
};

class PrintFunctionRangeConsumer : public ASTConsumer {
  CompilerInstance &Instance;
  std::optional<std::string> SavePath;

public:
  PrintFunctionRangeConsumer(CompilerInstance &Instance,
                             std::optional<std::string> SavePath)
      : Instance(Instance), SavePath(SavePath) {}

  void HandleTranslationUnit(ASTContext &context) override {
    for (auto &Decl : context.getTranslationUnitDecl()->decls()) {
      const auto &FileID =
          Instance.getSourceManager().getFileID(Decl->getLocation());
      if (FileID != Instance.getSourceManager().getMainFileID())
        continue;

      llvm::raw_fd_ostream *out;
      if (SavePath != std::nullopt) {
        std::error_code EC;
        out = new llvm::raw_fd_ostream(
            SavePath->c_str(), EC, llvm::sys::fs::CD_OpenAlways,
            llvm::sys::fs::FA_Write, llvm::sys::fs::OF_Text | llvm::sys::fs::OF_Append);
        if(EC.value()!=0){
          DiagnosticsEngine& DiagEng = Instance.getSema().getDiagnostics();
          int ID =DiagEng.getCustomDiagID(DiagnosticsEngine::Warning,
                                   "create file for dumping function range failed: %0");
          DiagEng.Report(ID) << SavePath->c_str();
          out = &llvm::errs();
        }
      } else {
        out = &llvm::errs();
      }
      FuncDeclVisitor v(*out, Instance);
      v.TraverseDecl(Decl);
      if(out != &llvm::errs()) {
        out->close();
        delete out;
      }
    }
  }
};

class PrintFunctionRangeAction : public PluginASTAction {
  std::optional<std::string> SavePath = std::nullopt;

protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 llvm::StringRef) override {
    return std::make_unique<PrintFunctionRangeConsumer>(CI, SavePath);
  }

  bool ParseArgs(const CompilerInstance &CI,
                 const std::vector<std::string> &args) override {
    if (!args.empty()) {
      SavePath = args[0];
    }
    return true;
  }
};

} // namespace

static FrontendPluginRegistry::Add<PrintFunctionRangeAction>
    X("FunctionRange", "print function range");
