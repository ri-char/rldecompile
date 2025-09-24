import asyncio
from enum import Enum

from rich import box
from rich.table import Table

from lib.utils import client, get_progress_bar, init_log


class ErrorType(Enum):
    UnmatchedFunction = "Call unmatched function"
    TypeError = "Type error"
    UseUndeclaredIdentifier = "Use undeclared identifier"
    GrammarError = "Grammar error"
    # RedefinitionVar = 7
    # FileNotFound = 8
    # NoReturnValue = 10
    # FunctionArgumentError = 11
    UnknownTypeName = "Unknown type name"
    WrongTemplate = "Use wrong template"
    Other = "Other"
    # InvalidASM = 13
    # DuplicateCaseValue = 14


def error_message_to_error_type(msg: str) -> ErrorType:
    if (
        msg.startswith("no matching function for call to ")
        or msg.startswith("no viable overloaded")
        or msg.startswith("reference to overloaded function could not be resolved")
        or msg == "builtin functions must be directly called"
        or msg.startswith("no matching literal operator for call")
        or msg.startswith(
            "exception specification in declaration does not match previous declaration"
        )
        or msg == "functions that differ only in their return type cannot be overloaded"
    ):
        return ErrorType.UnmatchedFunction
    if msg.startswith("too few arguments to function call") or msg.startswith(
        "too many arguments to function call"
    ):
        # return ErrorType.FunctionArgumentError
        return ErrorType.Other
    if msg.startswith("unknown type name"):
        return ErrorType.UnknownTypeName
    if msg.startswith("templates must have C++ linkage") or msg.startswith(
        "explicit specialization of undeclared template struct"
    ):
        return ErrorType.WrongTemplate

    if (
        "cannot be signed or unsigned" in msg
        or msg.startswith("invalid operands to")
        or msg.startswith("invalid argument type")
        or msg.startswith("cannot initialize a variable of type")
        or "conversion assigning to" in msg
        or "incompatible type" in msg
        or "indirection" in msg
        or msg.startswith("comparison between")
        or msg.startswith("cannot initialize")
        or msg.startswith("cannot assign to variable")
        or "cannot be narrowed to type" in msg
        or "must be a constant integer" in msg
        or msg.endswith("is not assignable")
        or msg == "subscripted value is not an array, pointer, or vector"
        or "cannot be narrowed from type" in msg
        or msg == "array subscript is not an integer"
        or "converts between" in msg
        or msg.startswith("member reference base type")
        or msg.startswith("conflicting types for")
        or msg.endswith("discards qualifiers")
        or msg.startswith("cast from")
        or msg.startswith("incompatible pointer types assigning to")
        or msg.startswith("called object type")
        or msg.startswith("ordered comparison between")
        or msg.startswith("variable has incomplete type")
        or msg.startswith("subscript of pointer to")
        or msg.startswith("array has incomplete element type")
        or msg.startswith("arithmetic on a pointer")
        or msg.startswith("non-const reference cannot bind to")
        or msg.startswith("no viable conversion from")
        or "incomplete type" in msg
        or msg.startswith("contextually convertible to")
        or msg.startswith("cannot combine with previous")
        or msg.startswith("must be a pointer to integer or pointer")
        or msg.startswith("static assertion failed")
        or msg.startswith("cannot increment value of type")
        or "outside the valid range" in msg
        or "is not contextually convertible to" in msg
        or msg == "a type specifier is required for all declarations"
        or msg.startswith(
            "address argument to atomic builtin must be a pointer to integer or pointer"
        )
        or msg.startswith(
            "default initialization of an object of const type 'int *const'"
        )
        or "cannot be narrowed to" in msg
        or msg.startswith("invalid type")
        or msg.startswith("initializer-string")
        or msg.startswith("static array size is a")
        or msg.endswith("changes address space of pointer")
        or "cast from" in msg
        or "conversion from" in msg
        or msg.startswith("left operand to ? is")
        or msg.startswith("comparison of distinct pointer types")
        or msg.startswith("default initialization of an object of")
        or msg == "excess elements in scalar initializer"
        or msg == "variable declaration in condition must have an initializer"
        or "compatible types" in msg
        or msg.startswith("explicit specialization of non-template class")
        or msg.startswith("member access into incomplete type")
    ):
        return ErrorType.TypeError
    if msg.startswith("duplicate case value"):
        # return ErrorType.DuplicateCaseValue
        return ErrorType.Other
    if msg.endswith("file not found"):
        # return ErrorType.FileNotFound
        return ErrorType.Other
    if (
        msg.startswith("use of undeclared identifier")
        or msg.startswith("no template named")
        or msg.startswith("no member named")
        or msg.startswith("use of undeclared label")
        or "declared in enclosing function" in msg
    ):
        return ErrorType.UseUndeclaredIdentifier
    if msg.startswith("redefinition of"):
        # return ErrorType.RedefinitionVar
        return ErrorType.Other
    if "should return a value" in msg or "should not return a value" in msg:
        # return ErrorType.NoReturnValue
        return ErrorType.Other
    if (
        msg.startswith("invalid instruction mnemonic")
        or msg == "invalid operand for instruction"
        or msg == "invalid operand number in inline asm string"
        or "in asm" in msg
        or msg == "invalid register name"
        or "input reg" in msg
        or msg == "unknown symbolic operand name in inline assembly string"
        or msg.startswith("more than one input constraint matches the same output")
    ):
        # return ErrorType.InvalidASM
        return ErrorType.Other
    if (
        msg == "hexadecimal floating literal requires an exponent"
        or msg
        == "asm-specifier for input or output variable conflicts with asm clobber list"
        or msg == "invalid % escape in inline assembly string"
        or msg == "namespaces can only be defined in global or namespace scope"
        or msg.startswith("invalid input constraint")
        or "'register' storage class specifier" in msg
        or msg.startswith("must use 'struct' tag to refer to type")
        or msg.startswith("arithmetic on a pointer to an incomplete type")
        or msg.startswith("used in type trait expression")
        or msg.startswith("invalid application of")
        or msg.startswith("invalid digit")
        or msg.endswith("is a keyword")
        or msg.startswith("statement requires expression of")
        or msg.startswith("unexpected character")
        or msg == "indirect goto in function with no address-of-label expressions"
        or msg == "integer literal is too large to be represented in any integer type"
        or msg.startswith("expected ")
        or msg.startswith("extraneous")
        or msg.startswith("unexpected token")
        or "at end of declaration" in msg
        or msg.startswith("unexpected type name")
        or msg == "excess elements in array initializer"
        or msg.endswith("not allowed in an identifier")
        or msg.startswith("invalid suffix")
        or msg == "function definition is not allowed here"
        or "attribute takes at least" in msg
        or msg == "exponent has no digits"
        or msg.endswith("statement not in switch statement")
        or msg == "unknown token in expression"
    ):
        return ErrorType.GrammarError
    # logger.warning(msg)
    return ErrorType.Other
    # raise Exception('unknown error type: ' + msg)


async def stat_for_one_optlevel(model_name: str, opt_level: str):
    process_bar = get_progress_bar(console=console)
    process_bar.start()
    stats: dict[ErrorType, int] = {v: 0 for v in ErrorType}
    count = await client["compile_error_type"].count_documents(
        {"model": model_name, "optLevel": opt_level, "error.0": {"$exists": True}}
    )
    t = process_bar.add_task(opt_level, total=count)
    total_error = 0
    async for obj in client["compile_error_type"].find(
        {"model": model_name, "optLevel": opt_level, "error.0": {"$exists": True}},
        projection={"_id": False, "error": True},
    ):
        errors = obj["error"]
        for err in errors:
            stats[error_message_to_error_type(err)] += 1
        total_error += 1
        process_bar.advance(t)
    process_bar.stop_task(t)
    process_bar.stop()

    table = Table(box=box.SIMPLE)
    for v in ErrorType:
        table.add_column(
            f"{v.name}",
            justify="right",
            style="green",
            no_wrap=True,
        )
    table.add_row(*[str(stats[v]) for v in ErrorType])
    console.print(table)
    with open("tmp/compile_error_type.txt", "a") as f:  # noqa: ASYNC230
        if f.tell() == 0:
            f.write("model_name,opt_level,")
            f.write(",".join([str(i.value) for i in ErrorType]) + "\n")
        f.write(model_name + "," + opt_level + ",")
        f.write(
            ",".join([f"{stats[i] / total_error * 100.0:.2f}" for i in ErrorType])
            + "\n"
        )


async def main():
    models = [
        "rldeompile-1.3b",
        "rldeompile-3b",
    ]
    for model in models:
        for opt_level in ["O0", "O1", "O2", "O3", "Os"]:
            await stat_for_one_optlevel(model, opt_level)


console = init_log()
asyncio.run(main())
