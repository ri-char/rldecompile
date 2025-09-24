import asyncio
import ctypes
import os
import pathlib
import re
import sys
import warnings

import apted
import tree_sitter
from tree_sitter import Language, Node, Parser


def get_language(language):
    try:
        module = __import__("tree_sitter_" + language)
        return Language(module.language())
    except ImportError:
        pass

    treesitter_path = os.environ.get("TREESITTER_PATH")
    if treesitter_path is None:
        raise RuntimeError("TREESITTER_PATH is not setted")
    if sys.platform == "win32":
        filename = f"{language}.dll"
    else:
        filename = f"{language}.so"
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    binary_path = str(pathlib.Path(treesitter_path) / filename)
    dll = ctypes.CDLL(binary_path)
    init_func = getattr(dll, f"tree_sitter_{language}")
    init_func.restype = ctypes.c_void_p
    gramma = init_func()
    language = Language(gramma)
    return language


c_parser = Parser(get_language("c"))


def find_error_node_counts(node: Node) -> int:
    error_nodes = 0
    if node.is_missing or node.is_error or node.is_extra:
        error_nodes += 1
    for child in node.children:
        if child.has_error:
            error_nodes += find_error_node_counts(child)
    return error_nodes


def check_is_function_definition(node: Node) -> bool:
    if node.type == "translation_unit":
        return node.child_count == 1 and node.child(0).type == "function_definition"  # type: ignore
    return node.type == "function_definition"


def get_argument_type(node: Node, code: bytes) -> list[str]:
    func_def_node: Node
    if node.type == "translation_unit":
        if node.child_count == 1 and node.child(0).type == "function_definition":  # type: ignore
            func_def_node: Node = node.child(0)  # type: ignore
        else:
            raise RuntimeError("code must be a single function")
    elif node.type == "function_definition":
        func_def_node = node
    else:
        raise RuntimeError("code must be a single function")
    return_type = func_def_node.child_by_field_name("type")

    def get_code_by_range(range: tuple[int, int]) -> bytes:
        return code[range[0] : range[1]]

    if return_type is None:
        return_type_str = ""
    else:
        return_type_str = get_code_by_range(return_type.byte_range).decode()

    def get_parameters_type() -> list[str]:
        dec_node = func_def_node.child_by_field_name("declarator")
        if dec_node is None:
            return []
        parameters_node = dec_node.child_by_field_name("parameters")
        if parameters_node is None:
            return []
        result = []
        for parameter_declaration_node in parameters_node.children:
            if parameter_declaration_node.type != "parameter_declaration":
                continue
            type_node = parameter_declaration_node.child_by_field_name("type")
            if type_node is None:
                result.append("")
            else:
                result.append(get_code_by_range(type_node.byte_range).decode())
        return result

    return [return_type_str] + get_parameters_type()


LINE_MARKER_PREPROC_RE = re.compile(rb"^#\s*[0-9]+\s*$")


def remove_c_comment(code_bytes: bytes) -> bytes:
    tree = c_parser.parse(code_bytes)
    root_node = tree.root_node
    comment_spans = []

    def traverse(node: Node):
        if node.type == "comment":
            comment_spans.append(node.byte_range)
        elif node.type == "preproc_call":
            # remove line marker
            preproc_directive = node.child_by_field_name("directive")
            if preproc_directive is not None:
                r = preproc_directive.byte_range
                preproc_directive_code = code_bytes[r[0] : r[1]]
                if LINE_MARKER_PREPROC_RE.match(preproc_directive_code):
                    comment_spans.append(node.byte_range)
        for child in node.children:
            traverse(child)

    traverse(root_node)
    for start, end in sorted(comment_spans, reverse=True):
        code_bytes = code_bytes[:start] + code_bytes[end:]

    return code_bytes


def remove_blank_lines(s: str) -> str:
    return "\n".join(line for line in s.splitlines() if line.strip())


def remove_intervals(text: bytes, intervals: list[tuple[int, int]]) -> bytes:
    """
    删除bytes中指定区间的内容

    Args:
        text: 原始字节数据
        intervals: 区间列表，每个区间为(start, end)的闭区间，从0开始计数

    Returns:
        删除指定区间后的字节数据
    """
    if not intervals:
        return text

    # 按起始位置排序区间
    sorted_intervals = sorted(intervals)

    # 合并重叠的区间
    merged = []
    for start, end in sorted_intervals:
        # 确保区间有效
        if start < 0 or end < 0 or start > end or start >= len(text):
            continue
        # 限制end不超过text长度
        end = min(end, len(text) - 1)

        if merged and start <= merged[-1][1] + 1:
            # 当前区间与上一个区间重叠或相邻，合并它们
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    # 从后往前删除，避免索引变化影响
    result = bytearray(text)
    for start, end in reversed(merged):
        del result[start : end + 1]  # end+1是因为是闭区间

    return bytes(result)


async def try_clang_format(text: bytes) -> bytes:
    p = await asyncio.create_subprocess_exec(
        "clang-format",
        stdout=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        if p.stdin is not None:
            p.stdin.write(text)
            p.stdin.close()
        stdout, stderr = await asyncio.wait_for(p.communicate(), timeout=60)
        if p.returncode != 0:
            return text
        return stdout
    except asyncio.TimeoutError:
        p.kill()
        return text


async def normalize_code(code: str | bytes) -> str:
    if isinstance(code, str):
        code = code.encode()
    return (
        await try_clang_format(
            remove_blank_lines(remove_c_comment(code).decode()).encode()
        )
    ).decode()


_EMPTY_FUNCTION_QUERY = tree_sitter.Query(
    get_language("c"),
    "(function_definition body: (compound_statement (_)* @exps_in_func))",
)


def is_empty_function(code: str) -> bool:
    node = c_parser.parse(code.encode()).root_node
    for _, match in _EMPTY_FUNCTION_QUERY.matches(node):
        if "exps_in_func" not in match:
            continue
        for expr in match["exps_in_func"]:
            if expr.type == "comment":
                continue
            if (
                expr.type == "expression_statement"
                and expr.child_count == 1
                and expr.child(0).type == ";"  # type: ignore
            ):
                continue
            return False
    return True


class TSEDNode:
    def __init__(self, name, path):
        self.id = path
        self.name = name
        self.children = []

    def add_child(self, node):
        self.children.append(node)


def _node_to_tsed_node(n: Node) -> tuple[TSEDNode, int]:
    tsed_node = TSEDNode(n.type, n.id)
    count = 1
    for child in n.children:
        child_node, child_count = _node_to_tsed_node(child)
        tsed_node.add_child(child_node)
        count += child_count
    return tsed_node, count


# https://github.com/Etamin/TSED/blob/main/TSED.py
def calculate_TSED(
    origin: str,
    target: str,
    deletion_weight: float,
    insertion_weight: float,
    rename_weight: float,
) -> float:
    """Calculates the TSED (Tree Similarity of Edit Distance) score between two
    trees using the APTED algorithm
    (http://tree-edit-distance.dbresearch.uni-salzburg.at.

    Args:
        origin (str): The origin string comprising a program.
        target (str): The destination string (i.e., the end-result after edit
            operations are applied) comprising a program.
        deletion_weight (float): The weight for deletion operations.
        insertion_weight (float): The weight for insertion operations.
        rename_weight (float): The weight for re-name operations.

    Returns:
        float: The TSED score computed for the two input trees.
    """
    tree1, len1 = _node_to_tsed_node(c_parser.parse(origin.encode()).root_node)
    tree2, len2 = _node_to_tsed_node(c_parser.parse(target.encode()).root_node)

    max_len = max(len1, len2)
    apted_result = apted.APTED(
        tree1,
        tree2,
        apted.PerEditOperationConfig(deletion_weight, insertion_weight, rename_weight),
    )
    res = apted_result.compute_edit_distance()
    if max_len > 0:
        if res > max_len:
            return 0.0
        else:
            return (max_len - res) / max_len
    else:
        return 1.0


if __name__ == "__main__":
    # code = "int main(int a, struct as b){}".encode()
    # node = c_parser.parse(code)
    # print(get_argument_type(node.root_node, code))
    print(
        remove_c_comment(
            b'int main(int argc, char**argv){\n    #43 "sddd"  \n    return argc*2;\n}'
        )
    )
