#!/usr/bin/env python3

import argparse
import os
from collections import Counter

from ghidra.app.util import NamespaceUtils
from ghidra.base.project import GhidraProject
from ghidra.framework.model import DomainFile
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.program.model.listing import (
    CommentType,
    Function,
    LocalVariableImpl,
    ParameterImpl,
    ReturnParameterImpl,
)
from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.util.task import TaskMonitor


DEFAULT_FUNCTION_PREFIXES = (
    "FUN_",
    "SUB_",
    "thunk_",
)

DEFAULT_LABEL_PREFIXES = (
    "DAT_",
    "LAB_",
    "UNK_",
    "OFF_",
    "PTR_",
    "caseD_",
    "switchD_",
    "uRam",
    "s_",
)


def is_default_function_name(name):
    return any(name.startswith(prefix) for prefix in DEFAULT_FUNCTION_PREFIXES)


def is_default_label_name(name):
    return any(name.startswith(prefix) for prefix in DEFAULT_LABEL_PREFIXES)


def is_meaningful_type(data_type):
    if data_type is None:
        return False
    name = data_type.getName()
    if name is None:
        return False
    lowered = str(name).lower()
    return lowered != "undefined" and not lowered.startswith("undefined")


def normalize_text(text):
    if text is None:
        return None
    text = str(text)
    return text if text else None


def mirror_namespace(dst_program, src_namespace):
    if src_namespace is None:
        return dst_program.getGlobalNamespace()
    try:
        source = src_namespace.getSymbol().getSource()
    except Exception:
        source = SourceType.USER_DEFINED
    return NamespaceUtils.createNamespaceHierarchy(
        src_namespace.getName(True), None, dst_program, source
    )


def resolve_data_type(src_data_type, dst_program):
    if src_data_type is None:
        return None
    dst_dtm = dst_program.getDataTypeManager()
    try:
        return dst_dtm.resolve(
            src_data_type.clone(dst_dtm), DataTypeConflictHandler.DEFAULT_HANDLER
        )
    except Exception:
        return None


def should_take_user_name(src_var):
    return src_var.getSource() == SourceType.USER_DEFINED


def storage_key(var):
    storage = var.getVariableStorage()
    return (
        storage.getSerializationString(),
        int(var.getFirstUseOffset()),
    )


def build_address_mapper(src_program, dst_program):
    src_base = src_program.getMinAddress().getOffset()
    dst_base = dst_program.getMinAddress().getOffset()
    delta = dst_base - src_base
    dst_space = dst_program.getMinAddress().getAddressSpace()

    def mapper(src_addr):
        return dst_space.getAddress(src_addr.getOffset() + delta)

    return mapper


class ProjectHandle(object):
    def __init__(self, ghidra_project=None, project=None, consumer=None):
        self.ghidra_project = ghidra_project
        self.project = project if project is not None else ghidra_project.getProject()
        self.project_data = (
            self.project.getProjectData()
            if project is not None
            else ghidra_project.getProjectData()
        )
        self.consumer = consumer if consumer is not None else self
        self.owned = ghidra_project is not None

    def getProjectData(self):
        return self.project_data

    def getProjectLocator(self):
        return self.project.getProjectLocator()

    def openProgram(self, folder_path, program_name, read_only):
        if self.ghidra_project is not None:
            return self.ghidra_project.openProgram(folder_path, program_name, read_only)

        full_path = folder_path.rstrip("/") + "/" + program_name
        if folder_path == "/":
            full_path = "/" + program_name
        domain_file = self.project_data.getFile(full_path)
        if domain_file is None:
            raise RuntimeError("missing project file: {}".format(full_path))
        if read_only:
            return domain_file.getReadOnlyDomainObject(
                self.consumer, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY
            )
        return domain_file.getDomainObject(self.consumer, False, False, TaskMonitor.DUMMY)

    def closeProgram(self, program):
        if self.ghidra_project is not None:
            self.ghidra_project.close(program)
        else:
            program.release(self.consumer)

    def close(self):
        if self.ghidra_project is not None:
            self.ghidra_project.close()


def maybe_current_project_handle(project_location, project_name):
    try:
        current_program = currentProgram
    except NameError:
        return None
    domain_file = current_program.getDomainFile()
    if domain_file is None:
        return None
    locator = domain_file.getProjectLocator()
    if locator is None:
        return None
    current_location = os.path.normpath(str(locator.getLocation()))
    expected_location = os.path.normpath(str(project_location))
    if current_location != expected_location:
        return None
    if locator.getName() != project_name:
        return None
    project_data = domain_file.getParent().getProjectData()

    class SessionProjectProxy(object):
        def __init__(self, locator, project_data):
            self._locator = locator
            self._project_data = project_data

        def getProjectLocator(self):
            return self._locator

        def getProjectData(self):
            return self._project_data

    return ProjectHandle(
        project=SessionProjectProxy(locator, project_data), consumer=domain_file
    )


def copy_comment_if_missing(src_text, get_dst_text, setter, stats, key):
    src_text = normalize_text(src_text)
    if not src_text:
        return False
    dst_text = normalize_text(get_dst_text())
    if dst_text:
        if dst_text != src_text:
            stats[key + "_conflicts"] += 1
        return False
    setter(src_text)
    stats[key] += 1
    return True


def merge_code_comments(src_program, dst_program, addr_map, stats):
    src_listing = src_program.getListing()
    dst_listing = dst_program.getListing()
    body = src_program.getMemory()

    for comment_type in CommentType.values():
        addr_iter = src_listing.getCommentAddressIterator(comment_type, body, True)
        while addr_iter.hasNext():
            addr = addr_iter.next()
            src_comment = normalize_text(src_listing.getComment(comment_type, addr))
            if not src_comment:
                continue
            dst_addr = addr_map(addr)
            dst_comment = normalize_text(dst_listing.getComment(comment_type, dst_addr))
            if dst_comment:
                if dst_comment != src_comment:
                    stats["comment_conflicts"] += 1
                continue
            dst_listing.setComment(dst_addr, comment_type, src_comment)
            stats["comments_copied"] += 1


def merge_bookmarks(src_program, dst_program, addr_map, stats):
    src_manager = src_program.getBookmarkManager()
    dst_manager = dst_program.getBookmarkManager()
    bookmark_iter = src_manager.getBookmarksIterator()
    while bookmark_iter.hasNext():
        bookmark = bookmark_iter.next()
        dst_addr = addr_map(bookmark.getAddress())
        existing = dst_manager.getBookmark(
            dst_addr, bookmark.getTypeString(), bookmark.getCategory()
        )
        if existing is not None:
            if normalize_text(existing.getComment()) != normalize_text(bookmark.getComment()):
                stats["bookmark_conflicts"] += 1
            continue
        dst_manager.setBookmark(
            dst_addr,
            bookmark.getTypeString(),
            bookmark.getCategory(),
            bookmark.getComment(),
        )
        stats["bookmarks_copied"] += 1


def merge_function_signature(src_func, dst_func, dst_program, stats):
    if src_func.getSignatureSource() != SourceType.USER_DEFINED:
        return False
    if dst_func.getSignatureSource() == SourceType.USER_DEFINED:
        return False

    params = []
    for src_param in src_func.getParameters():
        if src_param.isAutoParameter():
            continue
        params.append(ParameterImpl(src_param, dst_program))

    update_type = Function.FunctionUpdateType.CUSTOM_STORAGE
    if not src_func.hasCustomVariableStorage():
        update_type = Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS

    ret = ReturnParameterImpl(src_func.getReturn(), dst_program)
    dst_func.updateFunction(
        src_func.getCallingConventionName(),
        ret,
        params,
        update_type,
        True,
        SourceType.USER_DEFINED,
    )
    stats["signatures_copied"] += 1
    return True


def merge_variable_annotations(src_var, dst_var, dst_program, stats, kind):
    changed = False

    if should_take_user_name(src_var):
        src_name = str(src_var.getName())
        dst_name = str(dst_var.getName())
        if dst_var.getSource() != SourceType.USER_DEFINED:
            if src_name != dst_name:
                dst_var.setName(src_name, SourceType.USER_DEFINED)
                stats[kind + "_names_copied"] += 1
                changed = True
        elif src_name != dst_name:
            stats[kind + "_name_conflicts"] += 1

    src_comment = normalize_text(src_var.getComment())
    if src_comment:
        dst_comment = normalize_text(dst_var.getComment())
        if not dst_comment:
            dst_var.setComment(src_comment)
            stats[kind + "_comments_copied"] += 1
            changed = True
        elif dst_comment != src_comment:
            stats[kind + "_comment_conflicts"] += 1

    src_type = src_var.getDataType()
    dst_type = dst_var.getDataType()
    if is_meaningful_type(src_type) and not is_meaningful_type(dst_type):
        resolved = resolve_data_type(src_type, dst_program)
        if resolved is not None:
            dst_var.setDataType(resolved, SourceType.USER_DEFINED)
            stats[kind + "_types_copied"] += 1
            changed = True

    return changed


def merge_function_annotations(src_program, dst_program, addr_map, stats):
    src_listing = src_program.getListing()
    dst_listing = dst_program.getListing()
    src_iter = src_listing.getFunctions(True)

    while src_iter.hasNext():
        src_func = src_iter.next()
        dst_func = dst_listing.getFunctionAt(addr_map(src_func.getEntryPoint()))
        if dst_func is None:
            continue

        src_symbol = src_func.getSymbol()
        dst_symbol = dst_func.getSymbol()

        if src_symbol.getSource() == SourceType.USER_DEFINED:
            src_name = str(src_func.getName())
            dst_name = str(dst_func.getName())
            if dst_symbol.getSource() != SourceType.USER_DEFINED:
                if src_name != dst_name:
                    dst_func.setName(src_name, SourceType.USER_DEFINED)
                    stats["function_names_copied"] += 1
            elif src_name != dst_name:
                stats["function_name_conflicts"] += 1

        copy_comment_if_missing(
            src_func.getComment(),
            dst_func.getComment,
            dst_func.setComment,
            stats,
            "function_comments_copied",
        )
        copy_comment_if_missing(
            src_func.getRepeatableComment(),
            dst_func.getRepeatableComment,
            dst_func.setRepeatableComment,
            stats,
            "function_repeatable_comments_copied",
        )

        for tag in src_func.getTags():
            if dst_func.addTag(tag.getName()):
                stats["function_tags_copied"] += 1

        merge_function_signature(src_func, dst_func, dst_program, stats)

        if src_func.hasNoReturn() and not dst_func.hasNoReturn():
            dst_func.setNoReturn(True)
            stats["function_noreturn_copied"] += 1
        if src_func.isInline() and not dst_func.isInline():
            dst_func.setInline(True)
            stats["function_inline_copied"] += 1
        if src_func.hasVarArgs() and not dst_func.hasVarArgs():
            dst_func.setVarArgs(True)
            stats["function_varargs_copied"] += 1
        if src_func.isStackPurgeSizeValid() and not dst_func.isStackPurgeSizeValid():
            dst_func.setStackPurgeSize(src_func.getStackPurgeSize())
            stats["function_stack_purge_copied"] += 1

        src_params = [param for param in src_func.getParameters() if not param.isAutoParameter()]
        dst_params = [param for param in dst_func.getParameters() if not param.isAutoParameter()]
        for src_param, dst_param in zip(src_params, dst_params):
            merge_variable_annotations(src_param, dst_param, dst_program, stats, "param")

        src_locals = list(src_func.getLocalVariables())
        dst_locals = {storage_key(var): var for var in dst_func.getLocalVariables()}
        for src_local in src_locals:
            wants_annotation = (
                src_local.getSource() == SourceType.USER_DEFINED
                or normalize_text(src_local.getComment()) is not None
                or is_meaningful_type(src_local.getDataType())
            )
            if not wants_annotation:
                continue

            key = storage_key(src_local)
            dst_local = dst_locals.get(key)
            if dst_local is not None:
                merge_variable_annotations(src_local, dst_local, dst_program, stats, "local")
                continue

            try:
                resolved_type = resolve_data_type(src_local.getDataType(), dst_program)
                if resolved_type is None:
                    continue
                cloned_storage = src_local.getVariableStorage().clone(dst_program)
                new_local = LocalVariableImpl(
                    str(src_local.getName()),
                    int(src_local.getFirstUseOffset()),
                    resolved_type,
                    cloned_storage,
                    False,
                    dst_program,
                    SourceType.USER_DEFINED,
                )
                created = dst_func.addLocalVariable(new_local, SourceType.USER_DEFINED)
                created.setComment(src_local.getComment())
                stats["locals_created"] += 1
                dst_locals[key] = created
            except Exception:
                stats["local_create_failures"] += 1


def merge_user_symbols(src_program, dst_program, addr_map, stats):
    src_table = src_program.getSymbolTable()
    dst_table = dst_program.getSymbolTable()
    symbol_iter = src_table.getAllSymbols(False)

    while symbol_iter.hasNext():
        symbol = symbol_iter.next()
        if symbol.isDynamic() or symbol.isExternal():
            continue
        if symbol.getSource() != SourceType.USER_DEFINED:
            continue
        if symbol.getSymbolType() == SymbolType.FUNCTION:
            continue

        addr = addr_map(symbol.getAddress())
        namespace = mirror_namespace(dst_program, symbol.getParentNamespace())
        existing = dst_table.getSymbol(symbol.getName(), addr, namespace)
        if existing is not None:
            continue

        primary = dst_table.getPrimarySymbol(addr)
        try:
            if (
                primary is not None
                and primary.getSymbolType() != SymbolType.FUNCTION
                and primary.getSource() != SourceType.USER_DEFINED
            ):
                primary.setNameAndNamespace(
                    symbol.getName(), namespace, SourceType.USER_DEFINED
                )
                stats["symbol_names_copied"] += 1
                continue
        except Exception:
            pass

        try:
            created = dst_table.createLabel(
                addr, symbol.getName(), namespace, SourceType.USER_DEFINED
            )
            if (
                primary is None
                or primary.getSymbolType() != SymbolType.FUNCTION
                and primary.getSource() != SourceType.USER_DEFINED
            ):
                created.setPrimary()
            stats["symbols_created"] += 1
        except Exception:
            stats["symbol_conflicts"] += 1


def merge_program(src_project, dst_project, src_path, dst_path):
    src_folder, src_name = src_path.rsplit("/", 1)
    dst_folder, dst_name = dst_path.rsplit("/", 1)
    stats = Counter()

    src_program = src_project.openProgram(src_folder or "/", src_name, True)
    dst_program = dst_project.openProgram(dst_folder or "/", dst_name, False)
    tx = dst_program.startTransaction("Merge Blackbird annotations")
    commit = False

    try:
        if src_program.getLanguage() != dst_program.getLanguage():
            raise RuntimeError("language mismatch")
        src_size = src_program.getMaxAddress().getOffset() - src_program.getMinAddress().getOffset()
        dst_size = dst_program.getMaxAddress().getOffset() - dst_program.getMinAddress().getOffset()
        if src_size != dst_size:
            raise RuntimeError("address-range mismatch")
        addr_map = build_address_mapper(src_program, dst_program)

        merge_code_comments(src_program, dst_program, addr_map, stats)
        merge_bookmarks(src_program, dst_program, addr_map, stats)
        merge_function_annotations(src_program, dst_program, addr_map, stats)
        merge_user_symbols(src_program, dst_program, addr_map, stats)

        commit = True
        if dst_program.isChanged():
            dst_project.save(dst_program)
            stats["program_saved"] += 1
    finally:
        dst_program.endTransaction(tx, commit)
        src_project.closeProgram(src_program)
        dst_project.closeProgram(dst_program)

    return stats


def find_matching_programs(src_project, src_folder_path, dst_project, dst_folder_path):
    src_folder = src_project.getProjectData().getFolder(src_folder_path)
    dst_folder = dst_project.getProjectData().getFolder(dst_folder_path)
    if src_folder is None:
        raise RuntimeError("missing source folder: {}".format(src_folder_path))
    if dst_folder is None:
        raise RuntimeError("missing destination folder: {}".format(dst_folder_path))

    dst_files = {domain_file.getName(): domain_file for domain_file in dst_folder.getFiles()}
    matches = []
    skipped = []
    for src_file in src_folder.getFiles():
        name = src_file.getName()
        dst_file = dst_files.get(name)
        if dst_file is None:
            skipped.append(name)
            continue
        matches.append((src_file.getPathname(), dst_file.getPathname()))
    return matches, skipped


def script_argv():
    try:
        getter = getScriptArgs
    except NameError:
        return None
    try:
        return list(getter())
    except Exception:
        return None


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Merge user annotations between matching Ghidra programs."
    )
    parser.add_argument("--src-project-location", required=True)
    parser.add_argument("--src-project-name", required=True)
    parser.add_argument("--src-folder", default="/msn_binaries")
    parser.add_argument("--dst-project-location", required=True)
    parser.add_argument("--dst-project-name", required=True)
    parser.add_argument("--dst-folder", default="/")
    return parser.parse_args(argv)


def main():
    args = parse_args(script_argv())

    src_project = maybe_current_project_handle(
        args.src_project_location, args.src_project_name
    )
    if src_project is None:
        src_project = ProjectHandle(
            ghidra_project=GhidraProject.openProject(
                args.src_project_location, args.src_project_name, True
            )
        )

    dst_project = maybe_current_project_handle(
        args.dst_project_location, args.dst_project_name
    )
    if dst_project is None:
        dst_project = ProjectHandle(
            ghidra_project=GhidraProject.openProject(
                args.dst_project_location, args.dst_project_name, False
            )
        )

    total_stats = Counter()
    try:
        matches, skipped = find_matching_programs(
            src_project, args.src_folder, dst_project, args.dst_folder
        )
        print("matches={}".format(len(matches)))
        if skipped:
            print("skipped_missing_dst={}".format(",".join(sorted(skipped))))

        for src_path, dst_path in sorted(matches):
            print("MERGE {} -> {}".format(src_path, dst_path))
            stats = merge_program(src_project, dst_project, src_path, dst_path)
            total_stats.update(stats)
            summary = " ".join(
                "{}={}".format(key, stats[key]) for key in sorted(stats.keys()) if stats[key]
            )
            print("SUMMARY {} {}".format(dst_path, summary or "no_changes"))
    finally:
        src_project.close()
        dst_project.close()

    print("TOTAL")
    for key in sorted(total_stats.keys()):
        print("{}={}".format(key, total_stats[key]))


if __name__ == "__main__":
    main()
