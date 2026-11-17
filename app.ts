// GitHub REST v3, GraphQL v4 and git smart HTTP server for github-core-clone-01.
// stdlib only (node:http, node:crypto), TypeScript that Node 22 strips.

import { createHash, randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

const JSON_TYPE = 'application/json; charset=utf-8';
const DEFAULT_TOKEN = 'test-token';
const EXPECTED_TOKEN = process.env.MAKEFUN_SHOP_TOKEN || DEFAULT_TOKEN;

// ---------------------------------------------------------------------------------------------
// Types

interface User {
  id: number;
  login: string;
  name: string;
  email: string;
}

interface GitBlob {
  sha: string;
  data: Buffer;
  size: number;
}

interface GitTreeEntry {
  mode: string;
  name: string;
  sha: string;
  type: 'blob' | 'tree';
}

interface GitTree {
  sha: string;
  entries: GitTreeEntry[];
}

interface GitCommit {
  sha: string;
  tree: string;
  parents: string[];
  message: string;
  author: { name: string; email: string; date: string };
  committer: { name: string; email: string; date: string };
}

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}

interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: number;
  created_at: string;
  updated_at: string;
  user: { login: string; id: number };
}

interface PullRequest {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  head: { ref: string; sha: string };
  base: { ref: string; sha: string };
  merged: boolean;
  merged_at?: string;
  merge_commit_sha?: string;
  mergeable: boolean;
  created_at: string;
  updated_at: string;
  user: { login: string; id: number };
}

interface Comment {
  id: number;
  body: string;
  issue_number: number;
  created_at: string;
  updated_at: string;
  user: { login: string; id: number };
}

interface Repository {
  id: number;
  owner: string;
  name: string;
  description: string;
  private: boolean;
  default_branch: string;
  created_at: string;
  updated_at: string;
  branches: Map<string, string>; // branch name -> commit sha
  refs: Map<string, string>; // ref path -> commit sha
  labels: Map<string, Label>; // label name -> Label
  issues: Map<number, Issue>;
  issueCounter: number;
  pulls: Map<number, PullRequest>;
  pullCounter: number;
  comments: Map<number, Comment>;
  commentCounter: number;
}

// ---------------------------------------------------------------------------------------------
// Git Smart HTTP Types & Protocol

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';

const TYPE_CODE: Readonly<Record<GitObjectType, number>> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Readonly<Record<number, GitObjectType>> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const ZERO_OID = '0'.repeat(40);
const PKT_LINE_MAX = 65520;
const PKT_LINE_MAX_PAYLOAD = PKT_LINE_MAX - 4;

function asBuffer(value: string | Uint8Array): Buffer {
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  if (Buffer.isBuffer(value)) return value;
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function encodePktLine(payload: string | Uint8Array): Buffer {
  const data = asBuffer(payload);
  if (data.length > PKT_LINE_MAX_PAYLOAD) {
    throw new Error(`pkt-line payload is ${data.length} bytes, over max`);
  }
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

function encodePktLines(items: ReadonlyArray<string | Uint8Array | 'flush' | 'delim' | 'response-end'>): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(Buffer.from('0000', 'ascii'));
    else if (item === 'delim') parts.push(Buffer.from('0001', 'ascii'));
    else if (item === 'response-end') parts.push(Buffer.from('0002', 'ascii'));
    else parts.push(encodePktLine(item));
  }
  return Buffer.concat(parts);
}

function encodeSideband(band: number, data: Buffer): Buffer[] {
  const maxChunk = 65515;
  const packets: Buffer[] = [];
  let offset = 0;
  while (offset < data.length) {
    const chunk = data.subarray(offset, offset + maxChunk);
    const payload = Buffer.concat([Buffer.from([band]), chunk]);
    packets.push(encodePktLine(payload));
    offset += chunk.length;
  }
  return packets;
}

type GitPacket =
  | { readonly kind: 'data'; readonly payload: Buffer; readonly raw: Buffer }
  | { readonly kind: 'flush' }
  | { readonly kind: 'delim' }
  | { readonly kind: 'response-end' };

function decodePktLines(bytes: Uint8Array): GitPacket[] {
  const buffer = asBuffer(bytes);
  const packets: GitPacket[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) {
      throw new Error(`truncated pkt-line header: ${buffer.length - offset} bytes`);
    }
    const hex = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
      throw new Error(`invalid pkt-line length header ${hex}`);
    }
    const len = parseInt(hex, 16);
    if (len === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
    } else if (len === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
    } else if (len === 2) {
      packets.push({ kind: 'response-end' });
      offset += 4;
    } else if (len < 4 || len > PKT_LINE_MAX) {
      throw new Error(`invalid pkt-line length ${len}`);
    } else {
      if (offset + len > buffer.length) {
        throw new Error(`truncated pkt-line: announced ${len}, available ${buffer.length - offset}`);
      }
      const raw = buffer.subarray(offset, offset + len);
      packets.push({ kind: 'data', payload: raw.subarray(4), raw });
      offset += len;
    }
  }
  return packets;
}

function objectHeader(type: GitObjectType, size: number): Buffer {
  return Buffer.from(`${type} ${size}\0`, 'utf8');
}

function hashObject(type: GitObjectType, data: Uint8Array): string {
  const body = asBuffer(data);
  const hash = createHash('sha1');
  hash.update(objectHeader(type, body.length));
  hash.update(body);
  return hash.digest('hex');
}

interface TreeEntry {
  readonly mode: string;
  readonly name: string;
  readonly oid: string;
}

function parseTree(data: Uint8Array): TreeEntry[] {
  const buffer = asBuffer(data);
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    const space = buffer.indexOf(0x20, offset);
    if (space < 0) throw new Error('tree entry has no mode separator');
    const nul = buffer.indexOf(0x00, space + 1);
    if (nul < 0) throw new Error('tree entry has no name terminator');
    if (nul + 21 > buffer.length) throw new Error('tree entry has a truncated object id');
    const mode = buffer.subarray(offset, space).toString('ascii');
    const name = buffer.subarray(space + 1, nul).toString('utf8');
    const oid = buffer.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

interface CommitView {
  readonly tree: string;
  readonly parents: string[];
  readonly author: string;
  readonly committer: string;
  readonly message: string;
}

function parseCommit(data: Uint8Array): CommitView {
  const buffer = asBuffer(data);
  const blank = buffer.indexOf('\n\n');
  const headerEnd = blank < 0 ? buffer.length : blank;
  const headerText = buffer.subarray(0, headerEnd).toString('utf8');
  const message = blank < 0 ? '' : buffer.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of headerText.split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    const key = space < 0 ? line : line.slice(0, space);
    const value = space < 0 ? '' : line.slice(space + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  return { tree, parents, author, committer, message };
}

interface TagView {
  readonly object: string;
  readonly type: GitObjectType;
  readonly tag: string;
  readonly tagger: string;
  readonly message: string;
}

function parseTag(data: Uint8Array): TagView {
  const buffer = asBuffer(data);
  const blank = buffer.indexOf('\n\n');
  const headerEnd = blank < 0 ? buffer.length : blank;
  const headers = new Map<string, string>();
  for (const line of buffer.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    if (space < 0) continue;
    headers.set(line.slice(0, space), line.slice(space + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: (headers.get('type') ?? 'commit') as GitObjectType,
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : buffer.subarray(blank + 2).toString('utf8'),
  };
}

function parseIdentity(line: string): { name: string; email: string; date: string } {
  const match = /^([^<]+?)\s*<([^>]+)>\s*(\d+)\s*([+-]\d{4})?$/.exec(line.trim());
  if (match) {
    const timestamp = parseInt(match[3]!, 10);
    return {
      name: match[1]!.trim(),
      email: match[2]!.trim(),
      date: new Date(timestamp * 1000).toISOString(),
    };
  }
  return {
    name: 'Unknown',
    email: 'unknown@example.com',
    date: new Date().toISOString(),
  };
}

function readVarintSize(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  if (start >= buffer.length) throw new Error('pack entry has no size header');
  let byte = buffer[start]!;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while (byte & 0x80) {
    if (offset >= buffer.length) throw new Error('pack entry size varint is truncated');
    byte = buffer[offset++]!;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
    if (shift > 63) throw new Error('pack entry size varint is too long');
  }
  return { size, next: offset, first };
}

function readOfsDeltaBase(buffer: Buffer, start: number): { baseOffset: number; next: number } {
  if (start >= buffer.length) throw new Error('ofs-delta has no base offset');
  let byte = buffer[start]!;
  let offset = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    if (offset >= buffer.length) throw new Error('ofs-delta base offset is truncated');
    byte = buffer[offset++]!;
    value = ((value + 1) * 128) + (byte & 0x7f);
  }
  return { baseOffset: value, next: offset };
}

function inflateAt(buffer: Uint8Array, offset: number): { data: Buffer; next: number } {
  const view = asBuffer(buffer).subarray(offset);
  let result: { buffer: Buffer; engine: { bytesWritten: number } };
  try {
    result = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  } catch (err) {
    throw new Error(`zlib stream at offset ${offset} did not inflate: ${(err as Error).message}`);
  }
  const written = result.engine.bytesWritten;
  if (!written || written <= 0) throw new Error(`zlib stream at offset ${offset} consumed no bytes`);
  return { data: result.buffer, next: offset + written };
}

function applyDelta(base: Uint8Array, delta: Uint8Array): Buffer {
  const baseBuffer = asBuffer(base);
  const deltaBuffer = asBuffer(delta);
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (offset >= deltaBuffer.length) throw new Error('delta size varint is truncated');
      const byte = deltaBuffer[offset++]!;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
      if (shift > 63) throw new Error('delta size varint is too long');
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== baseBuffer.length) {
    throw new Error(`delta expects a ${sourceSize}-byte base, got ${baseBuffer.length}`);
  }
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < deltaBuffer.length) {
    const op = deltaBuffer[offset++]!;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) {
          if (offset >= deltaBuffer.length) throw new Error('delta copy offset is truncated');
          copyOffset += deltaBuffer[offset++]! * 2 ** shift;
        }
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) {
          if (offset >= deltaBuffer.length) throw new Error('delta copy size is truncated');
          copySize += deltaBuffer[offset++]! * 2 ** shift;
        }
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      if (copyOffset + copySize > baseBuffer.length) throw new Error('delta copy is out of base');
      if (written + copySize > targetSize) throw new Error('delta writes past target size');
      baseBuffer.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      if (offset + literal > deltaBuffer.length) throw new Error('delta insert is truncated');
      if (written + literal > targetSize) throw new Error('delta writes past target size');
      deltaBuffer.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0 is invalid');
    }
  }
  if (written !== targetSize) throw new Error(`delta produced ${written} of ${targetSize} bytes`);
  return out;
}

interface PackReadResult {
  readonly version: number;
  readonly declaredCount: number;
  readonly objects: Map<string, { type: GitObjectType; data: Buffer }>;
  readonly checksumOk: boolean;
}

function readPack(pack: Uint8Array, options: { resolveBase?: (oid: string) => { type: GitObjectType; data: Buffer } | undefined } = {}): PackReadResult {
  const buffer = asBuffer(pack);
  if (buffer.length < 32) throw new Error(`pack is ${buffer.length} bytes, too short`);
  if (buffer.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('pack does not start with PACK');
  }
  const version = buffer.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declaredCount = buffer.readUInt32BE(8);
  const trailerStart = buffer.length - 20;
  const trailer = buffer.subarray(trailerStart).toString('hex');
  const computedTrailer = createHash('sha1').update(buffer.subarray(0, trailerStart)).digest('hex');
  const checksumOk = trailer === computedTrailer;

  interface RawEntry {
    offset: number;
    typeCode: number;
    size: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
    resolvedType?: GitObjectType;
    resolved?: Buffer;
    oid?: string;
  }

  const raw: RawEntry[] = [];
  const byOffset = new Map<number, RawEntry>();
  let offset = 12;
  for (let index = 0; index < declaredCount; index += 1) {
    const entryOffset = offset;
    const header = readVarintSize(buffer, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: RawEntry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      const base = readOfsDeltaBase(buffer, offset);
      offset = base.next;
      if (base.baseOffset <= 0 || base.baseOffset > entryOffset) {
        throw new Error(`ofs-delta at ${entryOffset} names an invalid base offset`);
      }
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      if (offset + 20 > trailerStart) throw new Error('ref-delta base id is truncated');
      entry.baseOid = buffer.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`pack entry ${index} has unknown type code ${typeCode}`);
    }
    const inflated = inflateAt(buffer.subarray(0, trailerStart), offset);
    if (inflated.data.length !== header.size) {
      throw new Error(`pack entry declared ${header.size} bytes, inflated to ${inflated.data.length}`);
    }
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }

  const objects = new Map<string, { type: GitObjectType; data: Buffer }>();
  const resolving = new Set<number>();
  const resolvedByOid = new Map<string, RawEntry>();

  const resolve = (entry: RawEntry): { type: GitObjectType; data: Buffer; oid: string } => {
    if (entry.resolved && entry.resolvedType && entry.oid) {
      return { type: entry.resolvedType, data: entry.resolved, oid: entry.oid };
    }
    if (resolving.has(entry.offset)) throw new Error(`delta cycle at pack offset ${entry.offset}`);
    resolving.add(entry.offset);
    let type: GitObjectType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset!);
      if (!baseEntry) throw new Error(`ofs-delta base at offset ${entry.baseOffset} not in pack`);
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const wanted = entry.baseOid!;
      const baseEntry = resolvedByOid.get(wanted);
      if (baseEntry) {
        const base = resolve(baseEntry);
        type = base.type;
        data = applyDelta(base.data, entry.data);
      } else {
        const external = options.resolveBase?.(wanted);
        if (!external) {
          throw new Error(`ref-delta base ${wanted} not found`);
        }
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode]!;
      data = entry.data;
    }
    const oid = hashObject(type, data);
    entry.resolved = data;
    entry.resolvedType = type;
    entry.oid = oid;
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return { type, data, oid };
  };

  for (const entry of raw) {
    const resolved = resolve(entry);
    if (!objects.has(resolved.oid)) objects.set(resolved.oid, { type: resolved.type, data: resolved.data });
  }

  return { version, declaredCount, objects, checksumOk };
}

function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function writePack(objects: Iterable<{ type: GitObjectType; data: Uint8Array }>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const object of list) {
    const data = asBuffer(object.data);
    parts.push(writePackObjectHeader(object.type, data.length));
    parts.push(deflateSync(data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function collectReachable(
  roots: Iterable<string>,
  lookup: (oid: string) => { type: GitObjectType; data: Buffer } | undefined,
  seen: Set<string> = new Set<string>(),
  shallow: ReadonlySet<string> = new Set<string>(),
): Set<string> {
  const queue: string[] = [];
  for (const root of roots) if (root && root !== ZERO_OID) queue.push(root);
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (!object) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      if (!shallow.has(oid)) {
        for (const parent of commit.parents) queue.push(parent);
      }
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode === '160000') continue;
        queue.push(entry.oid);
      }
    }
  }
  return seen;
}

function isAncestor(ancestorSha: string, descendantSha: string): boolean {
  if (ancestorSha === descendantSha) return true;
  const visited = new Set<string>();
  const queue = [descendantSha];
  while (queue.length > 0) {
    const curr = queue.shift()!;
    if (curr === ancestorSha) return true;
    if (visited.has(curr)) continue;
    visited.add(curr);
    const commit = store.commits.get(curr);
    if (commit) {
      for (const p of commit.parents) queue.push(p);
    }
  }
  return false;
}

function readBodyBuffer(req: IncomingMessage): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function getPeeledSha(oid: string): string | null {
  const obj = store.objects.get(oid);
  if (!obj || obj.type !== 'tag') return null;
  let curr = obj;
  while (curr && curr.type === 'tag') {
    const parsed = parseTag(curr.data);
    const target = store.objects.get(parsed.object);
    if (!target) return parsed.object;
    if (target.type !== 'tag') return parsed.object;
    curr = target;
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// In-Memory Data Store

class ForgeStore {
  users = new Map<string, User>();
  repos = new Map<string, Repository>(); // `${owner.toLowerCase()}/${name.toLowerCase()}`
  userRepoList: Repository[] = []; // List of all repos for pagination order
  blobs = new Map<string, GitBlob>();
  trees = new Map<string, GitTree>();
  commits = new Map<string, GitCommit>();
  objects = new Map<string, { type: GitObjectType; data: Buffer }>();

  nextUserId = 1000;
  nextRepoId = 5000;
  nextLabelId = 1;
  nextCommentId = 1;

  constructor() {
    this.seed();
  }

  repoKey(owner: string, name: string): string {
    return `${owner.toLowerCase()}/${name.toLowerCase()}`;
  }

  getRepo(owner: string, name: string): Repository | undefined {
    return this.repos.get(this.repoKey(owner, name));
  }

  seed(): void {
    // Viewer user (seed scenario user)
    const viewer: User = {
      id: 1000,
      login: 'adaiversen',
      name: 'ada iversen',
      email: 'adaiversen@example.invalid',
    };
    this.users.set(viewer.login.toLowerCase(), viewer);

    // Octocat user
    const octocat: User = {
      id: 1,
      login: 'octocat',
      name: 'The Octocat',
      email: 'octocat@example.com',
    };
    this.users.set(octocat.login.toLowerCase(), octocat);

    // Octocat Hello-World repo
    const hwRepo: Repository = {
      id: 1,
      owner: 'octocat',
      name: 'Hello-World',
      description: 'Hello World',
      private: false,
      default_branch: 'main',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      branches: new Map(),
      refs: new Map(),
      labels: new Map(),
      issues: new Map(),
      issueCounter: 0,
      pulls: new Map(),
      pullCounter: 0,
      comments: new Map(),
      commentCounter: 0,
    };
    this.repos.set(this.repoKey(hwRepo.owner, hwRepo.name), hwRepo);
    this.userRepoList.push(hwRepo);

    // Initial commit for octocat/Hello-World
    const readmeContent = Buffer.from('# Hello-World\n\nHello World from Octocat!\n', 'utf-8');
    const blob = this.saveBlob(readmeContent);
    const tree = this.saveTree([
      { mode: '100644', name: 'README.md', sha: blob.sha, type: 'blob' },
    ]);
    const commit = this.saveCommit(
      tree.sha,
      [],
      'Initial commit',
      { name: octocat.name, email: octocat.email, date: new Date().toISOString() },
      { name: octocat.name, email: octocat.email, date: new Date().toISOString() },
    );
    hwRepo.branches.set('main', commit.sha);
    hwRepo.refs.set('refs/heads/main', commit.sha);
    hwRepo.labels.set('bug', { id: this.nextLabelId++, name: 'bug', color: 'd73a4a', description: "Something isn't working" });
  }

  saveBlob(data: Buffer): GitBlob {
    const header = Buffer.from(`blob ${data.length}\0`);
    const sha = createHash('sha1').update(Buffer.concat([header, data])).digest('hex');
    const blob: GitBlob = { sha, data, size: data.length };
    this.blobs.set(sha, blob);
    this.objects.set(sha, { type: 'blob', data });
    return blob;
  }

  saveTree(entries: GitTreeEntry[]): GitTree {
    const sorted = [...entries].sort((a, b) => {
      const nameA = a.type === 'tree' ? a.name + '/' : a.name;
      const nameB = b.type === 'tree' ? b.name + '/' : b.name;
      return nameA < nameB ? -1 : nameA > nameB ? 1 : 0;
    });
    const parts: Buffer[] = [];
    for (const e of sorted) {
      parts.push(Buffer.from(`${e.mode} ${e.name}\0`));
      parts.push(Buffer.from(e.sha, 'hex'));
    }
    const body = Buffer.concat(parts);
    const header = Buffer.from(`tree ${body.length}\0`);
    const sha = createHash('sha1').update(Buffer.concat([header, body])).digest('hex');
    const tree: GitTree = { sha, entries: sorted };
    this.trees.set(sha, tree);
    this.objects.set(sha, { type: 'tree', data: body });
    return tree;
  }

  saveCommit(
    treeSha: string,
    parents: string[],
    message: string,
    author: { name: string; email: string; date: string },
    committer: { name: string; email: string; date: string },
  ): GitCommit {
    const authorTime = Math.floor(new Date(author.date).getTime() / 1000);
    const committerTime = Math.floor(new Date(committer.date).getTime() / 1000);
    let commitText = `tree ${treeSha}\n`;
    for (const p of parents) {
      commitText += `parent ${p}\n`;
    }
    commitText += `author ${author.name} <${author.email}> ${authorTime} +0000\n`;
    commitText += `committer ${committer.name} <${committer.email}> ${committerTime} +0000\n\n`;
    commitText += `${message}\n`;

    const body = Buffer.from(commitText, 'utf-8');
    const header = Buffer.from(`commit ${body.length}\0`);
    const sha = createHash('sha1').update(Buffer.concat([header, body])).digest('hex');
    const commit: GitCommit = {
      sha,
      tree: treeSha,
      parents,
      message,
      author,
      committer,
    };
    this.commits.set(sha, commit);
    this.objects.set(sha, { type: 'commit', data: body });
    return commit;
  }

  saveBlobRaw(sha: string, data: Buffer): void {
    this.objects.set(sha, { type: 'blob', data });
    this.blobs.set(sha, { sha, data, size: data.length });
  }

  saveTreeRaw(sha: string, data: Buffer): void {
    this.objects.set(sha, { type: 'tree', data });
    const entries = parseTree(data);
    this.trees.set(sha, {
      sha,
      entries: entries.map((e) => ({
        mode: e.mode,
        name: e.name,
        sha: e.oid,
        type: e.mode === '40000' ? 'tree' : 'blob',
      })),
    });
  }

  saveCommitRaw(sha: string, data: Buffer): void {
    this.objects.set(sha, { type: 'commit', data });
    const parsed = parseCommit(data);
    const authorParsed = parseIdentity(parsed.author);
    const committerParsed = parseIdentity(parsed.committer);
    this.commits.set(sha, {
      sha,
      tree: parsed.tree,
      parents: parsed.parents,
      message: parsed.message,
      author: authorParsed,
      committer: committerParsed,
    });
  }

  saveTagRaw(sha: string, data: Buffer): void {
    this.objects.set(sha, { type: 'tag', data });
  }

  flattenTree(treeSha: string, prefix = ''): Map<string, { sha: string; mode: string }> {
    const result = new Map<string, { sha: string; mode: string }>();
    const tree = this.trees.get(treeSha);
    if (!tree) return result;
    for (const entry of tree.entries) {
      const fullPath = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.type === 'blob') {
        result.set(fullPath, { sha: entry.sha, mode: entry.mode });
      } else if (entry.type === 'tree') {
        const sub = this.flattenTree(entry.sha, fullPath);
        for (const [k, v] of sub) {
          result.set(k, v);
        }
      }
    }
    return result;
  }

  buildTreeFromFiles(files: Map<string, { sha: string; mode?: string }>): string {
    interface DirNode {
      files: Map<string, { sha: string; mode: string }>;
      dirs: Map<string, DirNode>;
    }
    const root: DirNode = { files: new Map(), dirs: new Map() };

    for (const [path, entry] of files) {
      const parts = path.split('/').filter(Boolean);
      if (parts.length === 0) continue;
      let curr = root;
      for (let i = 0; i < parts.length - 1; i++) {
        const part = parts[i]!;
        let next = curr.dirs.get(part);
        if (!next) {
          next = { files: new Map(), dirs: new Map() };
          curr.dirs.set(part, next);
        }
        curr = next;
      }
      const fileName = parts[parts.length - 1]!;
      curr.files.set(fileName, { sha: entry.sha, mode: entry.mode || '100644' });
    }

    const writeNode = (node: DirNode): string => {
      const entries: GitTreeEntry[] = [];
      for (const [dirName, dirNode] of node.dirs) {
        const subSha = writeNode(dirNode);
        entries.push({ mode: '40000', name: dirName, sha: subSha, type: 'tree' });
      }
      for (const [fileName, file] of node.files) {
        entries.push({ mode: file.mode, name: fileName, sha: file.sha, type: 'blob' });
      }
      return this.saveTree(entries).sha;
    };

    return writeNode(root);
  }

  getFilesAtCommit(commitSha: string): Map<string, { sha: string; mode: string }> {
    const commit = this.commits.get(commitSha);
    if (!commit) return new Map();
    return this.flattenTree(commit.tree);
  }

  findCommonAncestor(sha1: string, sha2: string): string | null {
    if (sha1 === sha2) return sha1;
    const ancestors1 = new Set<string>();
    const q1 = [sha1];
    while (q1.length > 0) {
      const curr = q1.shift()!;
      if (ancestors1.has(curr)) continue;
      ancestors1.add(curr);
      const c = this.commits.get(curr);
      if (c) {
        for (const p of c.parents) q1.push(p);
      }
    }

    const q2 = [sha2];
    const visited2 = new Set<string>();
    while (q2.length > 0) {
      const curr = q2.shift()!;
      if (visited2.has(curr)) continue;
      visited2.add(curr);
      if (ancestors1.has(curr)) return curr;
      const c = this.commits.get(curr);
      if (c) {
        for (const p of c.parents) q2.push(p);
      }
    }
    return null;
  }
}

// Global store instance
const store = new ForgeStore();

// ---------------------------------------------------------------------------------------------
// HTTP Helpers

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Readonly<Record<string, string>> = {}, reqId?: string): void {
  const text = `${JSON.stringify(body)}\n`;
  const resHeaders: Record<string, string> = {
    'content-type': JSON_TYPE,
    'content-length': String(Buffer.byteLength(text)),
    'x-github-request-id': reqId || randomUUID(),
    ...headers,
  };
  res.writeHead(status, resHeaders);
  res.end(text);
}

function sendEmpty(res: ServerResponse, status: number, headers: Readonly<Record<string, string>> = {}, reqId?: string): void {
  res.writeHead(status, {
    'x-github-request-id': reqId || randomUUID(),
    ...headers,
  });
  res.end();
}

function paginate<T>(
  req: IncomingMessage,
  res: ServerResponse,
  items: readonly T[],
  reqId: string,
  extraHeaders: Readonly<Record<string, string>> = {},
): void {
  const url = new URL(req.url ?? '/', `http://${req.headers.host || 'localhost'}`);
  const perPageRaw = parseInt(url.searchParams.get('per_page') || '30', 10);
  const perPage = isNaN(perPageRaw) || perPageRaw < 1 ? 30 : Math.min(100, perPageRaw);
  const pageRaw = parseInt(url.searchParams.get('page') || '1', 10);
  const page = isNaN(pageRaw) || pageRaw < 1 ? 1 : pageRaw;

  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  const start = (page - 1) * perPage;
  const pageItems = items.slice(start, start + perPage);

  const makeLinkUrl = (p: number): string => {
    const u = new URL(url.pathname, `http://${req.headers.host || 'localhost'}`);
    for (const [k, v] of url.searchParams.entries()) {
      if (k !== 'page' && k !== 'per_page') u.searchParams.set(k, v);
    }
    u.searchParams.set('page', String(p));
    u.searchParams.set('per_page', String(perPage));
    return u.toString();
  };

  const linkParts: string[] = [];
  if (page < totalPages) {
    linkParts.push(`<${makeLinkUrl(page + 1)}>; rel="next"`);
    linkParts.push(`<${makeLinkUrl(totalPages)}>; rel="last"`);
  }
  if (page > 1) {
    linkParts.push(`<${makeLinkUrl(1)}>; rel="first"`);
    linkParts.push(`<${makeLinkUrl(page - 1)}>; rel="prev"`);
  }

  const headers: Record<string, string> = {
    'x-total-count': String(total),
    ...extraHeaders,
  };
  if (linkParts.length > 0) {
    headers.link = linkParts.join(', ');
  }

  sendJson(res, 200, pageItems, headers, reqId);
}

async function readBody(req: IncomingMessage): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

// ---------------------------------------------------------------------------------------------
// Formatting Helpers

function repoJson(repo: Repository): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: {
      login: repo.owner,
      id: store.users.get(repo.owner.toLowerCase())?.id || 1000,
    },
    private: repo.private,
    description: repo.description,
    default_branch: repo.default_branch,
    created_at: repo.created_at,
    updated_at: repo.updated_at,
  };
}

function issueJson(issue: Issue, repo: Repository): Record<string, unknown> {
  const labelObjs = issue.labels.map((name) => {
    const l = repo.labels.get(name);
    return { id: l?.id || 1, name, color: l?.color || 'ededed' };
  });
  return {
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: labelObjs,
    comments: issue.comments,
    created_at: issue.created_at,
    updated_at: issue.updated_at,
    user: issue.user,
  };
}

function pullJson(pull: PullRequest, repo: Repository): Record<string, unknown> {
  // Head sha is latest tip of head branch if available
  const headSha = repo.branches.get(pull.head.ref) || pull.head.sha;
  const baseSha = repo.branches.get(pull.base.ref) || pull.base.sha;

  const res: Record<string, unknown> = {
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    head: { ref: pull.head.ref, sha: pull.merged ? pull.head.sha : headSha },
    base: { ref: pull.base.ref, sha: pull.merged ? pull.base.sha : baseSha },
    merged: pull.merged,
    mergeable: pull.mergeable,
    created_at: pull.created_at,
    updated_at: pull.updated_at,
    user: pull.user,
  };
  if (pull.merged) {
    res.merged_at = pull.merged_at;
    res.merge_commit_sha = pull.merge_commit_sha;
  }
  return res;
}

// Shared writes for REST and GraphQL: both surfaces operate on the same records and git objects.
function createIssueRecord(repo: Repository, viewer: User, title: string, body: string, labels: string[] = []): Issue {
  const now = new Date().toISOString();
  const issue: Issue = {
    number: ++repo.issueCounter,
    title,
    body,
    state: 'open',
    labels,
    comments: 0,
    created_at: now,
    updated_at: now,
    user: { login: viewer.login, id: viewer.id },
  };
  repo.issues.set(issue.number, issue);
  return issue;
}

function createCommentRecord(repo: Repository, viewer: User, subject: Issue | PullRequest, body: string): Comment {
  const now = new Date().toISOString();
  const comment: Comment = {
    id: store.nextCommentId++,
    body,
    issue_number: subject.number,
    created_at: now,
    updated_at: now,
    user: { login: viewer.login, id: viewer.id },
  };
  repo.comments.set(comment.id, comment);
  if ('comments' in subject) subject.comments++;
  subject.updated_at = now;
  return comment;
}

function createPullRecord(repo: Repository, viewer: User, title: string, body: string, head: string, base: string): PullRequest | null {
  const headSha = repo.branches.get(head) || repo.refs.get(head);
  const baseSha = repo.branches.get(base) || repo.refs.get(base);
  if (!headSha || !baseSha) return null;
  const now = new Date().toISOString();
  const pull: PullRequest = {
    number: ++repo.pullCounter,
    title,
    body,
    state: 'open',
    head: { ref: head, sha: headSha },
    base: { ref: base, sha: baseSha },
    merged: false,
    mergeable: true,
    created_at: now,
    updated_at: now,
    user: { login: viewer.login, id: viewer.id },
  };
  repo.pulls.set(pull.number, pull);
  return pull;
}

function mergePullRecord(
  repo: Repository,
  pull: PullRequest,
  viewer: User,
  commitTitle?: string,
  mergeMethod: string = 'SQUASH',
): GitCommit | null {
  const currentBaseSha = repo.branches.get(pull.base.ref) || pull.base.sha;
  const currentHeadSha = repo.branches.get(pull.head.ref) || pull.head.sha;
  const ancestorSha = store.findCommonAncestor(currentBaseSha, currentHeadSha) || pull.base.sha;
  const ancestorFiles = store.getFilesAtCommit(ancestorSha);
  const baseFiles = store.getFilesAtCommit(currentBaseSha);
  const headFiles = store.getFilesAtCommit(currentHeadSha);

  const allPaths = new Set([...ancestorFiles.keys(), ...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of allPaths) {
    const ancestor = ancestorFiles.get(path)?.sha;
    const base = baseFiles.get(path)?.sha;
    const head = headFiles.get(path)?.sha;
    if (base !== ancestor && head !== ancestor && base !== head) return null;
  }

  const mergedFiles = new Map<string, { sha: string; mode: string }>(baseFiles);
  for (const [path, entry] of headFiles) mergedFiles.set(path, entry);
  for (const [path] of ancestorFiles) {
    if (!headFiles.has(path) && baseFiles.get(path)?.sha === ancestorFiles.get(path)?.sha) {
      mergedFiles.delete(path);
    }
  }

  const newTreeSha = store.buildTreeFromFiles(mergedFiles);
  const mergeCommit = store.saveCommit(
    newTreeSha,
    mergeMethod === 'MERGE' ? [currentBaseSha, currentHeadSha] : [currentBaseSha],
    commitTitle || `Merge pull request #${pull.number} from ${pull.head.ref}`,
    { name: viewer.name, email: viewer.email, date: new Date().toISOString() },
    { name: viewer.name, email: viewer.email, date: new Date().toISOString() },
  );
  repo.branches.set(pull.base.ref, mergeCommit.sha);
  repo.refs.set(`refs/heads/${pull.base.ref}`, mergeCommit.sha);
  pull.state = 'closed';
  pull.merged = true;
  pull.merged_at = new Date().toISOString();
  pull.merge_commit_sha = mergeCommit.sha;
  pull.updated_at = pull.merged_at;
  return mergeCommit;
}

// ---------------------------------------------------------------------------------------------
// GraphQL v4: a small document parser, schema validator and selection-set executor.

type GraphQLInputValue =
  | { kind: 'literal'; value: unknown }
  | { kind: 'variable'; name: string }
  | { kind: 'list'; values: GraphQLInputValue[] }
  | { kind: 'object'; fields: Record<string, GraphQLInputValue> };

interface GraphQLField {
  kind: 'field';
  name: string;
  alias: string;
  args: Record<string, GraphQLInputValue>;
  selections: GraphQLSelection[];
}

type GraphQLSelection = GraphQLField
  | { kind: 'fragment'; type: string; selections: GraphQLSelection[] }
  | { kind: 'spread'; name: string };

interface GraphQLOperation {
  type: 'query' | 'mutation';
  name?: string;
  variables: Array<{ name: string; type: string; defaultValue?: GraphQLInputValue }>;
  selections: GraphQLSelection[];
}

interface GraphQLDocument {
  operations: GraphQLOperation[];
  fragments: Record<string, { type: string; selections: GraphQLSelection[] }>;
}

interface GraphQLToken {
  kind: 'name' | 'string' | 'number' | 'punct' | 'eof';
  value: string;
}

function tokenizeGraphQL(query: string): GraphQLToken[] {
  const tokens: GraphQLToken[] = [];
  let offset = 0;
  while (offset < query.length) {
    const char = query[offset]!;
    if (/[\s,\uFEFF]/.test(char)) { offset++; continue; }
    if (char === '#') {
      while (offset < query.length && query[offset] !== '\n' && query[offset] !== '\r') offset++;
      continue;
    }
    if (query.startsWith('...', offset)) {
      tokens.push({ kind: 'punct', value: '...' });
      offset += 3;
      continue;
    }
    if (char === '"') {
      const start = offset++;
      let closed = false;
      while (offset < query.length) {
        if (query[offset] === '\\') { offset += 2; continue; }
        if (query[offset++] === '"') { closed = true; break; }
      }
      if (!closed) throw new Error('Unterminated GraphQL string');
      tokens.push({ kind: 'string', value: JSON.parse(query.slice(start, offset)) });
      continue;
    }
    const name = /^[A-Za-z_][A-Za-z0-9_]*/.exec(query.slice(offset));
    if (name) {
      tokens.push({ kind: 'name', value: name[0] });
      offset += name[0].length;
      continue;
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(query.slice(offset));
    if (number) {
      tokens.push({ kind: 'number', value: number[0] });
      offset += number[0].length;
      continue;
    }
    if ('!$():=[]{}'.includes(char)) {
      tokens.push({ kind: 'punct', value: char });
      offset++;
      continue;
    }
    throw new Error(`Unexpected GraphQL character ${JSON.stringify(char)}`);
  }
  tokens.push({ kind: 'eof', value: '<EOF>' });
  return tokens;
}

class GraphQLParser {
  private readonly tokens: GraphQLToken[];
  private offset = 0;

  constructor(query: string) { this.tokens = tokenizeGraphQL(query); }

  private peek(): GraphQLToken { return this.tokens[this.offset]!; }

  private accept(value: string): boolean {
    const token = this.peek();
    if ((token.kind === 'punct' || token.kind === 'name') && token.value === value) {
      this.offset++;
      return true;
    }
    return false;
  }

  private expect(value: string): void {
    if (!this.accept(value)) throw new Error(`Expected ${value}, found ${this.peek().value}`);
  }

  private name(): string {
    const token = this.peek();
    if (token.kind !== 'name') throw new Error(`Expected a GraphQL name, found ${token.value}`);
    this.offset++;
    return token.value;
  }

  private type(): string {
    let type: string;
    if (this.accept('[')) { type = `[${this.type()}]`; this.expect(']'); }
    else type = this.name();
    return this.accept('!') ? `${type}!` : type;
  }

  private value(): GraphQLInputValue {
    if (this.accept('$')) return { kind: 'variable', name: this.name() };
    if (this.accept('[')) {
      const values: GraphQLInputValue[] = [];
      while (!this.accept(']')) values.push(this.value());
      return { kind: 'list', values };
    }
    if (this.accept('{')) {
      const fields: Record<string, GraphQLInputValue> = Object.create(null);
      while (!this.accept('}')) {
        const name = this.name();
        this.expect(':');
        if (Object.hasOwn(fields, name)) throw new Error(`Duplicate input field ${name}`);
        fields[name] = this.value();
      }
      return { kind: 'object', fields };
    }
    const token = this.peek();
    this.offset++;
    if (token.kind === 'string') return { kind: 'literal', value: token.value };
    if (token.kind === 'number') return { kind: 'literal', value: Number(token.value) };
    if (token.kind === 'name') {
      const value = token.value === 'null' ? null : token.value === 'true' ? true : token.value === 'false' ? false : token.value;
      return { kind: 'literal', value };
    }
    throw new Error(`Expected a GraphQL value, found ${token.value}`);
  }

  private selections(): GraphQLSelection[] {
    this.expect('{');
    const selections: GraphQLSelection[] = [];
    while (!this.accept('}')) {
      if (this.accept('...')) {
        if (this.accept('on')) selections.push({ kind: 'fragment', type: this.name(), selections: this.selections() });
        else selections.push({ kind: 'spread', name: this.name() });
        continue;
      }
      const first = this.name();
      const name = this.accept(':') ? this.name() : first;
      const args: Record<string, GraphQLInputValue> = Object.create(null);
      if (this.accept('(')) {
        while (!this.accept(')')) {
          const arg = this.name();
          this.expect(':');
          if (Object.hasOwn(args, arg)) throw new Error(`Duplicate argument ${arg}`);
          args[arg] = this.value();
        }
      }
      const children = this.peek().value === '{' ? this.selections() : [];
      selections.push({ kind: 'field', name, alias: first, args, selections: children });
    }
    if (selections.length === 0) throw new Error('A GraphQL selection set cannot be empty');
    return selections;
  }

  parse(): GraphQLDocument {
    const operations: GraphQLOperation[] = [];
    const fragments: GraphQLDocument['fragments'] = Object.create(null);
    while (this.peek().kind !== 'eof') {
      if (this.accept('fragment')) {
        const name = this.name();
        this.expect('on');
        const type = this.name();
        if (Object.hasOwn(fragments, name)) throw new Error(`Duplicate fragment ${name}`);
        fragments[name] = { type, selections: this.selections() };
        continue;
      }
      if (this.peek().value === '{') {
        operations.push({ type: 'query', variables: [], selections: this.selections() });
        continue;
      }
      const type = this.name();
      if (type !== 'query' && type !== 'mutation') throw new Error(`Unsupported operation ${type}`);
      const name = this.peek().kind === 'name' ? this.name() : undefined;
      const variables: GraphQLOperation['variables'] = [];
      if (this.accept('(')) {
        while (!this.accept(')')) {
          this.expect('$');
          const variableName = this.name();
          this.expect(':');
          const variableType = this.type();
          const defaultValue = this.accept('=') ? this.value() : undefined;
          if (variables.some((variable) => variable.name === variableName)) throw new Error(`Duplicate variable $${variableName}`);
          variables.push({ name: variableName, type: variableType, defaultValue });
        }
      }
      if (name && operations.some((operation) => operation.name === name)) throw new Error(`Duplicate operation ${name}`);
      operations.push({ type, name, variables, selections: this.selections() });
    }
    if (operations.length === 0) throw new Error('No GraphQL operation was provided');
    return { operations, fragments };
  }
}

// These tables drive both validation and introspection, so advertised fields are executable.
const GRAPHQL_FIELDS: Record<string, Record<string, string>> = {
  Query: { viewer: 'User!', repository: 'Repository', node: 'Node', __type: '__Type' },
  Mutation: {
    createIssue: 'CreateIssuePayload', closeIssue: 'CloseIssuePayload', createPullRequest: 'CreatePullRequestPayload',
    mergePullRequest: 'MergePullRequestPayload', addComment: 'AddCommentPayload',
  },
  Repository: {
    id: 'ID!', databaseId: 'Int!', name: 'String!', nameWithOwner: 'String!', owner: 'User!', defaultBranchRef: 'Ref',
    viewerPermission: 'RepositoryPermission', hasIssuesEnabled: 'Boolean!', issue: 'Issue', issues: 'IssueConnection!',
    pullRequests: 'PullRequestConnection!', pullRequest: 'PullRequest',
  },
  Issue: { id: 'ID!', number: 'Int!', title: 'String!', state: 'IssueState!', body: 'String!' },
  IssueConnection: { nodes: '[Issue!]!', pageInfo: 'PageInfo!' },
  PageInfo: { hasNextPage: 'Boolean!', endCursor: 'String' },
  PullRequest: {
    id: 'ID!', number: 'Int!', state: 'PullRequestState!', merged: 'Boolean!', headRefName: 'String!',
    baseRefName: 'String!', mergeable: 'MergeableState!', files: 'PullRequestChangedFileConnection!',
  },
  PullRequestConnection: { nodes: '[PullRequest!]!' },
  PullRequestChangedFileConnection: { nodes: '[PullRequestChangedFile!]!' },
  PullRequestChangedFile: { path: 'String!' },
  User: { login: 'String!' },
  Ref: { name: 'String!' },
  Node: { id: 'ID!' },
  CreateIssuePayload: { issue: 'Issue' },
  CloseIssuePayload: { issue: 'Issue' },
  CreatePullRequestPayload: { pullRequest: 'PullRequest' },
  MergePullRequestPayload: { pullRequest: 'PullRequest' },
  AddCommentPayload: { commentEdge: 'IssueCommentEdge' },
  IssueCommentEdge: { node: 'IssueComment' },
  IssueComment: { id: 'ID!', body: 'String!' },
  __Type: { name: 'String!', kind: '__TypeKind!', fields: '[__Field!]', enumValues: '[__EnumValue!]' },
  __Field: { name: 'String!' },
  __EnumValue: { name: 'String!' },
};

const GRAPHQL_ARGS: Record<string, Record<string, string>> = {
  'Query.repository': { owner: 'String!', name: 'String!' },
  'Query.node': { id: 'ID!' },
  'Query.__type': { name: 'String!' },
  'Repository.issue': { number: 'Int!' },
  'Repository.issues': { first: 'Int', states: '[IssueState!]', orderBy: 'IssueOrder', after: 'String' },
  'Repository.pullRequests': { first: 'Int' },
  'Repository.pullRequest': { number: 'Int!' },
  'PullRequest.files': { first: 'Int' },
  '__Type.fields': { includeDeprecated: 'Boolean' },
  '__Type.enumValues': { includeDeprecated: 'Boolean' },
  'Mutation.createIssue': { input: 'CreateIssueInput!' },
  'Mutation.closeIssue': { input: 'CloseIssueInput!' },
  'Mutation.createPullRequest': { input: 'CreatePullRequestInput!' },
  'Mutation.mergePullRequest': { input: 'MergePullRequestInput!' },
  'Mutation.addComment': { input: 'AddCommentInput!' },
};

const GRAPHQL_INPUTS: Record<string, Record<string, string>> = {
  IssueOrder: { field: 'IssueOrderField!', direction: 'OrderDirection!' },
  CreateIssueInput: { repositoryId: 'ID!', title: 'String!', body: 'String' },
  CloseIssueInput: { issueId: 'ID!' },
  CreatePullRequestInput: { repositoryId: 'ID!', baseRefName: 'String!', headRefName: 'String!', title: 'String!' },
  MergePullRequestInput: { pullRequestId: 'ID!', mergeMethod: 'PullRequestMergeMethod' },
  AddCommentInput: { subjectId: 'ID!', body: 'String!' },
};

const GRAPHQL_ENUMS: Record<string, readonly string[]> = {
  IssueState: ['OPEN', 'CLOSED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
  __TypeKind: ['SCALAR', 'OBJECT', 'INTERFACE', 'UNION', 'ENUM', 'INPUT_OBJECT', 'LIST', 'NON_NULL'],
};

function graphQLTypeKind(name: string): string | null {
  if (Object.hasOwn(GRAPHQL_ENUMS, name)) return 'ENUM';
  if (Object.hasOwn(GRAPHQL_INPUTS, name)) return 'INPUT_OBJECT';
  if (name === 'Node') return 'INTERFACE';
  if (Object.hasOwn(GRAPHQL_FIELDS, name)) return 'OBJECT';
  return ['String', 'ID', 'Int', 'Float', 'Boolean'].includes(name) ? 'SCALAR' : null;
}

function graphQLRecord(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function graphQLInput(value: GraphQLInputValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'literal': return value.value;
    case 'variable':
      if (!Object.hasOwn(variables, value.name)) throw new Error(`Variable $${value.name} is not defined`);
      return variables[value.name];
    case 'list': return value.values.map((entry) => graphQLInput(entry, variables));
    case 'object': return Object.fromEntries(Object.entries(value.fields).map(([name, entry]) => [name, graphQLInput(entry, variables)]));
  }
}

function coerceGraphQLInput(value: unknown, type: string, label: string): any {
  if (type.endsWith('!')) {
    if (value === null || value === undefined) throw new Error(`${label} of type ${type} is required`);
    return coerceGraphQLInput(value, type.slice(0, -1), label);
  }
  const namedType = type.replace(/[\[\]!]/g, '');
  if (!Object.hasOwn(GRAPHQL_INPUTS, namedType) && !Object.hasOwn(GRAPHQL_ENUMS, namedType)
    && !['String', 'ID', 'Int', 'Float', 'Boolean'].includes(namedType)) {
    throw new Error(`Unknown GraphQL input type ${namedType}`);
  }
  if (value === null || value === undefined) return value;
  if (type.startsWith('[')) {
    const entries = Array.isArray(value) ? value : [value];
    return entries.map((entry, index) => coerceGraphQLInput(entry, type.slice(1, -1), `${label}[${index}]`));
  }
  if (Object.hasOwn(GRAPHQL_INPUTS, type)) {
    if (!graphQLRecord(value)) throw new Error(`${label} must be an input object`);
    const fields = GRAPHQL_INPUTS[type]!;
    for (const name of Object.keys(value)) {
      if (!Object.hasOwn(fields, name)) throw new Error(`Unknown field ${name} on input type ${type}`);
    }
    return Object.fromEntries(Object.entries(fields).map(([name, fieldType]) => [name, coerceGraphQLInput(value[name], fieldType, `${label}.${name}`)]));
  }
  if (Object.hasOwn(GRAPHQL_ENUMS, type)) {
    if (typeof value !== 'string' || !GRAPHQL_ENUMS[type]!.includes(value)) throw new Error(`${label} is not a valid ${type}`);
    return value;
  }
  if (type === 'ID' && (typeof value === 'string' || (typeof value === 'number' && Number.isInteger(value)))) return String(value);
  if (type === 'String' && typeof value === 'string') return value;
  if (type === 'Boolean' && typeof value === 'boolean') return value;
  if (type === 'Int' && typeof value === 'number' && Number.isInteger(value) && value >= -2147483648 && value <= 2147483647) return value;
  if (type === 'Float' && typeof value === 'number' && Number.isFinite(value)) return value;
  throw new Error(`${label} must be of type ${type}`);
}

function graphQLArguments(type: string, field: GraphQLField, variables: Record<string, unknown>): Record<string, any> {
  const schema = GRAPHQL_ARGS[`${type}.${field.name}`] ?? {};
  for (const name of Object.keys(field.args)) {
    if (!Object.hasOwn(schema, name)) throw new Error(`Unknown argument ${name} on field ${type}.${field.name}`);
  }
  return Object.fromEntries(Object.entries(schema).map(([name, argType]) => {
    const value = Object.hasOwn(field.args, name) ? graphQLInput(field.args[name]!, variables) : undefined;
    return [name, coerceGraphQLInput(value, argType, `Argument ${type}.${field.name}(${name}:)`)];
  }));
}

function validateGraphQLSelections(
  type: string,
  selections: GraphQLSelection[],
  variables: Record<string, unknown>,
  fragments: GraphQLDocument['fragments'],
  stack: string[] = [],
): void {
  for (const selection of selections) {
    if (selection.kind !== 'field') {
      const fragment = selection.kind === 'fragment' ? selection : fragments[selection.name];
      if (!fragment) throw new Error(`Unknown fragment ${selection.kind === 'spread' ? selection.name : ''}`);
      if (!Object.hasOwn(GRAPHQL_FIELDS, fragment.type)) throw new Error(`Unknown fragment type ${fragment.type}`);
      if (selection.kind === 'spread' && stack.includes(selection.name)) throw new Error(`Fragment cycle at ${selection.name}`);
      if (type !== fragment.type && type !== 'Node' && fragment.type !== 'Node') throw new Error(`Fragment on ${fragment.type} cannot apply to ${type}`);
      validateGraphQLSelections(fragment.type, fragment.selections, variables, fragments,
        selection.kind === 'spread' ? [...stack, selection.name] : stack);
      continue;
    }
    const fields = GRAPHQL_FIELDS[type]!;
    const fieldType = selection.name === '__typename' ? 'String!' : Object.hasOwn(fields, selection.name) ? fields[selection.name] : undefined;
    if (!fieldType) throw new Error(`Cannot query field "${selection.name}" on type "${type}"`);
    graphQLArguments(type, selection, variables);
    const namedType = fieldType.replace(/[\[\]!]/g, '');
    if (Object.hasOwn(GRAPHQL_FIELDS, namedType)) {
      if (selection.selections.length === 0) throw new Error(`Field ${type}.${selection.name} requires a selection set`);
      validateGraphQLSelections(namedType, selection.selections, variables, fragments, stack);
    } else if (selection.selections.length > 0) {
      throw new Error(`Field ${type}.${selection.name} cannot have a selection set`);
    }
  }
}

interface GraphQLObject {
  type: string;
  value: any;
  repo?: Repository;
}

function graphQLObject(type: string, value: any, repo?: Repository): GraphQLObject | null {
  return value === null || value === undefined ? null : { type, value, repo };
}

function graphQLId(type: string, databaseId: number, number?: number): string {
  return Buffer.from(`${type}:${databaseId}${number === undefined ? '' : `:${number}`}`, 'utf8').toString('base64');
}

function graphQLNode(id: string): GraphQLObject | null {
  const decoded = Buffer.from(id, 'base64').toString('utf8');
  const match = /^(Repository|Issue|PullRequest|IssueComment|User):(\d+)(?::(\d+))?$/.exec(decoded);
  if (!match) return null;
  const type = match[1]!;
  const databaseId = Number(match[2]);
  const number = match[3] === undefined ? undefined : Number(match[3]);
  if (graphQLId(type, databaseId, number) !== id) return null;
  if (type === 'User') return graphQLObject('User', [...store.users.values()].find((user) => user.id === databaseId));
  const repo = [...store.repos.values()].find((entry) => entry.id === databaseId);
  if (!repo) return null;
  if (type === 'Repository' && number === undefined) return graphQLObject(type, repo);
  if (number === undefined) return null;
  const value = type === 'Issue' ? repo.issues.get(number) : type === 'PullRequest' ? repo.pulls.get(number)
    : type === 'IssueComment' ? repo.comments.get(number) : undefined;
  return graphQLObject(type, value, repo);
}

function requireGraphQLNode(id: string, type: string): GraphQLObject {
  const node = graphQLNode(id);
  if (!node || node.type !== type) throw new Error(`Could not resolve ${type} node ${id}`);
  return node;
}

function graphQLFirst(args: Record<string, any>): number {
  const first = args.first ?? 30;
  if (first < 0 || first > 100) throw new Error('Argument first must be between 0 and 100');
  return first;
}

function graphQLIssues(repo: Repository, args: Record<string, any>): GraphQLObject {
  let issues = [...repo.issues.values()];
  if (args.states) issues = issues.filter((issue) => args.states.includes(issue.state.toUpperCase()));
  const order = args.orderBy ?? { field: 'CREATED_AT', direction: 'DESC' };
  const key = (issue: Issue): number => order.field === 'COMMENTS' ? issue.comments
    : Date.parse(order.field === 'UPDATED_AT' ? issue.updated_at : issue.created_at);
  issues.sort((a, b) => (key(a) - key(b) || a.number - b.number) * (order.direction === 'ASC' ? 1 : -1));
  let start = 0;
  if (args.after !== undefined && args.after !== null) {
    const index = issues.findIndex((issue) => graphQLId('IssueCursor', repo.id, issue.number) === args.after);
    if (index < 0) throw new Error('Invalid issues cursor');
    start = index + 1;
  }
  const page = issues.slice(start, start + graphQLFirst(args));
  const last = page[page.length - 1];
  return graphQLObject('IssueConnection', {
    nodes: page.map((issue) => graphQLObject('Issue', issue, repo)),
    pageInfo: graphQLObject('PageInfo', {
      hasNextPage: start + page.length < issues.length,
      endCursor: last ? graphQLId('IssueCursor', repo.id, last.number) : null,
    }),
  })!;
}

function graphQLPullFiles(repo: Repository, pull: PullRequest, args: Record<string, any>): GraphQLObject {
  const headFiles = store.getFilesAtCommit(repo.branches.get(pull.head.ref) || pull.head.sha);
  const baseFiles = store.getFilesAtCommit(repo.branches.get(pull.base.ref) || pull.base.sha);
  const paths = [...new Set([...headFiles.keys(), ...baseFiles.keys()])].filter((path) => {
    const head = headFiles.get(path);
    const base = baseFiles.get(path);
    return head?.sha !== base?.sha || head?.mode !== base?.mode;
  }).sort();
  return graphQLObject('PullRequestChangedFileConnection', {
    nodes: paths.slice(0, graphQLFirst(args)).map((path) => graphQLObject('PullRequestChangedFile', { path })),
  })!;
}

function resolveGraphQLMutation(name: string, input: Record<string, any>, viewer: User): GraphQLObject {
  if (name === 'createIssue') {
    const repo = requireGraphQLNode(input.repositoryId, 'Repository').value as Repository;
    const issue = createIssueRecord(repo, viewer, input.title, input.body ?? '');
    return graphQLObject('CreateIssuePayload', { issue: graphQLObject('Issue', issue, repo) })!;
  }
  if (name === 'closeIssue') {
    const node = requireGraphQLNode(input.issueId, 'Issue');
    const issue = node.value as Issue;
    issue.state = 'closed';
    issue.updated_at = new Date().toISOString();
    return graphQLObject('CloseIssuePayload', { issue: node })!;
  }
  if (name === 'createPullRequest') {
    const repo = requireGraphQLNode(input.repositoryId, 'Repository').value as Repository;
    const pull = createPullRecord(repo, viewer, input.title, '', input.headRefName, input.baseRefName);
    if (!pull) throw new Error('Invalid head or base branch');
    return graphQLObject('CreatePullRequestPayload', { pullRequest: graphQLObject('PullRequest', pull, repo) })!;
  }
  if (name === 'mergePullRequest') {
    const node = requireGraphQLNode(input.pullRequestId, 'PullRequest');
    const pull = node.value as PullRequest;
    if (pull.state !== 'open' || pull.merged) throw new Error('Pull request is not open');
    if (!mergePullRecord(node.repo!, pull, viewer, undefined, input.mergeMethod ?? 'MERGE')) {
      throw new Error('Pull request cannot be merged due to conflict');
    }
    return graphQLObject('MergePullRequestPayload', { pullRequest: node })!;
  }
  const subject = graphQLNode(input.subjectId);
  if (!subject || (subject.type !== 'Issue' && subject.type !== 'PullRequest')) throw new Error('Could not resolve comment subject');
  const comment = createCommentRecord(subject.repo!, viewer, subject.value, input.body);
  return graphQLObject('AddCommentPayload', {
    commentEdge: graphQLObject('IssueCommentEdge', { node: graphQLObject('IssueComment', comment, subject.repo) }),
  })!;
}

function resolveGraphQLField(source: GraphQLObject, name: string, args: Record<string, any>, viewer: User): any {
  if (name === '__typename') return source.type;
  if (source.type === 'Query') {
    if (name === 'viewer') return graphQLObject('User', viewer);
    if (name === 'repository') return graphQLObject('Repository', store.getRepo(args.owner, args.name));
    if (name === 'node') return graphQLNode(args.id);
    return graphQLTypeKind(args.name) ? graphQLObject('__Type', { name: args.name }) : null;
  }
  if (source.type === 'Mutation') return resolveGraphQLMutation(name, args.input, viewer);
  if (source.type === 'Repository') {
    const repo = source.value as Repository;
    if (name === 'id') return graphQLId('Repository', repo.id);
    if (name === 'databaseId') return repo.id;
    if (name === 'name') return repo.name;
    if (name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
    if (name === 'owner') return graphQLObject('User', { login: repo.owner });
    if (name === 'defaultBranchRef') return repo.branches.has(repo.default_branch) ? graphQLObject('Ref', { name: repo.default_branch }) : null;
    if (name === 'viewerPermission') return repo.owner.toLowerCase() === viewer.login.toLowerCase() ? 'ADMIN' : 'READ';
    if (name === 'hasIssuesEnabled') return true;
    if (name === 'issue') return graphQLObject('Issue', repo.issues.get(args.number), repo);
    if (name === 'issues') return graphQLIssues(repo, args);
    if (name === 'pullRequest') return graphQLObject('PullRequest', repo.pulls.get(args.number), repo);
    return graphQLObject('PullRequestConnection', {
      nodes: [...repo.pulls.values()].sort((a, b) => b.number - a.number).slice(0, graphQLFirst(args))
        .map((pull) => graphQLObject('PullRequest', pull, repo)),
    });
  }
  if (source.type === 'Issue') {
    if (name === 'id') return graphQLId('Issue', source.repo!.id, source.value.number);
    if (name === 'state') return source.value.state.toUpperCase();
  }
  if (source.type === 'PullRequest') {
    const pull = source.value as PullRequest;
    if (name === 'id') return graphQLId('PullRequest', source.repo!.id, pull.number);
    if (name === 'state') return pull.merged ? 'MERGED' : pull.state.toUpperCase();
    if (name === 'headRefName') return pull.head.ref;
    if (name === 'baseRefName') return pull.base.ref;
    if (name === 'mergeable') return pull.mergeable ? 'MERGEABLE' : 'CONFLICTING';
    if (name === 'files') return graphQLPullFiles(source.repo!, pull, args);
  }
  if (source.type === 'IssueComment' && name === 'id') return graphQLId('IssueComment', source.repo!.id, source.value.id);
  if (source.type === '__Type') {
    const type = source.value.name as string;
    if (name === 'kind') return graphQLTypeKind(type);
    if (name === 'fields') return Object.hasOwn(GRAPHQL_FIELDS, type)
      ? Object.keys(GRAPHQL_FIELDS[type]!).map((field) => graphQLObject('__Field', { name: field })) : null;
    if (name === 'enumValues') return Object.hasOwn(GRAPHQL_ENUMS, type)
      ? GRAPHQL_ENUMS[type]!.map((value) => graphQLObject('__EnumValue', { name: value })) : null;
  }
  return source.value[name];
}

function executeGraphQLSelections(
  source: GraphQLObject,
  selections: GraphQLSelection[],
  variables: Record<string, unknown>,
  fragments: GraphQLDocument['fragments'],
  viewer: User,
): Record<string, unknown> {
  // Merge repeated response keys before resolving them, so a mutation is executed once.
  const fields = new Map<string, GraphQLField>();
  const collect = (entries: GraphQLSelection[]): void => {
    for (const selection of entries) {
      if (selection.kind !== 'field') {
        const fragment = selection.kind === 'fragment' ? selection : fragments[selection.name]!;
        if (fragment.type === source.type || fragment.type === 'Node') collect(fragment.selections);
        continue;
      }
      const previous = fields.get(selection.alias);
      if (previous) {
        if (previous.name !== selection.name || JSON.stringify(previous.args) !== JSON.stringify(selection.args)) {
          throw new Error(`Conflicting fields for response key ${selection.alias}`);
        }
        previous.selections.push(...selection.selections);
      } else fields.set(selection.alias, { ...selection, selections: [...selection.selections] });
    }
  };
  collect(selections);
  const result: Record<string, unknown> = Object.create(null);
  for (const field of fields.values()) {
    const value = resolveGraphQLField(source, field.name, graphQLArguments(source.type, field, variables), viewer);
    const project = (entry: any): unknown => entry === null || entry === undefined ? null : Array.isArray(entry)
      ? entry.map(project) : typeof entry === 'object' ? executeGraphQLSelections(entry, field.selections, variables, fragments, viewer) : entry;
    result[field.alias] = project(value);
  }
  return result;
}

function executeGraphQL(request: unknown, viewer: User): Record<string, unknown> {
  try {
    if (!graphQLRecord(request) || typeof request.query !== 'string') throw new Error('A GraphQL operation requires a query string');
    if (request.variables !== undefined && request.variables !== null && !graphQLRecord(request.variables)) {
      throw new Error('GraphQL variables must be an object');
    }
    if (request.operationName !== undefined && request.operationName !== null && typeof request.operationName !== 'string') {
      throw new Error('GraphQL operationName must be a string');
    }
    const document = new GraphQLParser(request.query).parse();
    const operation = request.operationName ? document.operations.find((entry) => entry.name === request.operationName)
      : document.operations.length === 1 ? document.operations[0] : undefined;
    if (!operation) throw new Error(request.operationName ? `Unknown operation ${request.operationName}` : 'An operationName is required for multiple operations');
    const variables: Record<string, unknown> = Object.create(null);
    for (const variable of operation.variables) {
      const value = Object.hasOwn(request.variables ?? {}, variable.name) ? request.variables[variable.name]
        : variable.defaultValue ? graphQLInput(variable.defaultValue, {}) : undefined;
      variables[variable.name] = coerceGraphQLInput(value, variable.type, `Variable $${variable.name}`);
    }
    const type = operation.type === 'mutation' ? 'Mutation' : 'Query';
    // Validate the entire selection tree before reads or writes, including nullable branches.
    validateGraphQLSelections(type, operation.selections, variables, document.fragments);
    return { data: executeGraphQLSelections(graphQLObject(type, {})!, operation.selections, variables, document.fragments, viewer) };
  } catch (err) {
    return { errors: [{ message: err instanceof Error ? err.message : String(err) }] };
  }
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse, reqId: string): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !/^Bearer\s+(.+)$/i.test(authHeader) || authHeader.replace(/^Bearer\s+/i, '').trim() !== EXPECTED_TOKEN) {
    sendJson(res, 401, { message: 'Bad credentials' }, {}, reqId);
    return;
  }
  if (req.method !== 'POST') {
    sendJson(res, 405, { message: 'Method Not Allowed' }, { allow: 'POST' }, reqId);
    return;
  }
  let body: unknown;
  try { body = JSON.parse(await readBody(req)); }
  catch { sendJson(res, 400, { message: 'Problems parsing JSON' }, {}, reqId); return; }
  const viewer = store.users.get('adaiversen')!;
  sendJson(res, 200, Array.isArray(body) ? body.map((operation) => executeGraphQL(operation, viewer)) : executeGraphQL(body, viewer), {}, reqId);
}

// ---------------------------------------------------------------------------------------------
// Git Smart HTTP Handlers

function handleInfoRefs(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repository,
  service: string,
): void {
  if (service === 'git-upload-pack') {
    const gitProtocol = req.headers['git-protocol'];
    const isV2 = typeof gitProtocol === 'string' && gitProtocol.split(':').some((p) => p.trim() === 'version=2');

    if (isV2) {
      res.writeHead(200, {
        'content-type': 'application/x-git-upload-pack-advertisement',
        'cache-control': 'no-cache, max-age=0, must-revalidate',
      });
      res.end(
        encodePktLines([
          'version 2\n',
          'agent=git/makefun\n',
          'ls-refs=unborn\n',
          'fetch=shallow\n',
          'object-format=sha1\n',
          'flush',
        ]),
      );
      return;
    }

    // Protocol V0 upload-pack
    const lines: Array<string | Buffer | 'flush'> = ['# service=git-upload-pack\n', 'flush'];
    const branchEntries = [...repo.branches.entries()].sort(([a], [b]) => a.localeCompare(b));
    const tagEntries = [...repo.refs.entries()]
      .filter(([name]) => name.startsWith('refs/tags/'))
      .sort(([a], [b]) => a.localeCompare(b));

    const defaultBranch = repo.default_branch || 'main';
    const headSha = repo.branches.get(defaultBranch) || (branchEntries.length > 0 ? branchEntries[0]![1] : null);

    const v0Caps = `multi_ack_detailed no-done side-band-64k ofs-delta agent=git/makefun symref=HEAD:refs/heads/${defaultBranch} object-format=sha1`;

    if (!headSha && branchEntries.length === 0 && tagEntries.length === 0) {
      lines.push(
        `0000000000000000000000000000000000000000 capabilities^{}\0multi_ack_detailed no-done side-band-64k ofs-delta agent=git/makefun object-format=sha1\n`,
      );
      lines.push('flush');
    } else {
      if (headSha) {
        lines.push(`${headSha} HEAD\0${v0Caps}\n`);
        for (const [bName, bSha] of branchEntries) {
          lines.push(`${bSha} refs/heads/${bName}\n`);
        }
      } else {
        const [firstBName, firstBSha] = branchEntries[0]!;
        lines.push(`${firstBSha} refs/heads/${firstBName}\0${v0Caps}\n`);
        for (let i = 1; i < branchEntries.length; i++) {
          const [bName, bSha] = branchEntries[i]!;
          lines.push(`${bSha} refs/heads/${bName}\n`);
        }
      }
      for (const [tRef, tSha] of tagEntries) {
        lines.push(`${tSha} ${tRef}\n`);
        const peeled = getPeeledSha(tSha);
        if (peeled) {
          lines.push(`${peeled} ${tRef}^{}\n`);
        }
      }
      lines.push('flush');
    }

    res.writeHead(200, {
      'content-type': 'application/x-git-upload-pack-advertisement',
      'cache-control': 'no-cache, max-age=0, must-revalidate',
    });
    res.end(encodePktLines(lines));
    return;
  }

  if (service === 'git-receive-pack') {
    const recvCaps = 'report-status report-status-v2 delete-refs side-band-64k ofs-delta agent=git/makefun object-format=sha1';
    const lines: Array<string | Buffer | 'flush'> = ['# service=git-receive-pack\n', 'flush'];
    const branchEntries = [...repo.branches.entries()].sort(([a], [b]) => a.localeCompare(b));
    const tagEntries = [...repo.refs.entries()]
      .filter(([name]) => name.startsWith('refs/tags/'))
      .sort(([a], [b]) => a.localeCompare(b));

    if (branchEntries.length === 0 && tagEntries.length === 0) {
      lines.push(`0000000000000000000000000000000000000000 capabilities^{}\0${recvCaps}\n`);
      lines.push('flush');
    } else {
      let first = true;
      for (const [bName, bSha] of branchEntries) {
        if (first) {
          lines.push(`${bSha} refs/heads/${bName}\0${recvCaps}\n`);
          first = false;
        } else {
          lines.push(`${bSha} refs/heads/${bName}\n`);
        }
      }
      for (const [tRef, tSha] of tagEntries) {
        if (first) {
          lines.push(`${tSha} ${tRef}\0${recvCaps}\n`);
          first = false;
        } else {
          lines.push(`${tSha} ${tRef}\n`);
        }
        const peeled = getPeeledSha(tSha);
        if (peeled) {
          lines.push(`${peeled} ${tRef}^{}\n`);
        }
      }
      lines.push('flush');
    }

    res.writeHead(200, {
      'content-type': 'application/x-git-receive-pack-advertisement',
      'cache-control': 'no-cache, max-age=0, must-revalidate',
    });
    res.end(encodePktLines(lines));
    return;
  }
}

async function handleUploadPack(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repository,
): Promise<void> {
  const rawBody = await readBodyBuffer(req);
  const packets = decodePktLines(rawBody);

  const firstPacket = packets.find((p) => p.kind === 'data');
  const firstLine = firstPacket && firstPacket.kind === 'data' ? firstPacket.payload.toString('utf8').replace(/\n$/, '') : '';

  if (firstLine.startsWith('command=ls-refs')) {
    let peel = false;
    let symrefs = false;
    let unborn = false;
    const prefixes: string[] = [];

    let inArgs = false;
    for (const p of packets) {
      if (p.kind === 'delim') {
        inArgs = true;
        continue;
      }
      if (!inArgs) continue;
      if (p.kind === 'data') {
        const text = p.payload.toString('utf8').replace(/\n$/, '');
        if (text === 'peel') peel = true;
        else if (text === 'symrefs') symrefs = true;
        else if (text === 'unborn') unborn = true;
        else if (text.startsWith('ref-prefix ')) {
          prefixes.push(text.slice('ref-prefix '.length));
        }
      }
    }

    interface RefEntry {
      name: string;
      line: string;
    }
    const refCandidates: RefEntry[] = [];
    const defaultBranch = repo.default_branch || 'main';
    const headSha = repo.branches.get(defaultBranch);

    if (repo.branches.size === 0) {
      if (unborn) {
        refCandidates.push({
          name: 'HEAD',
          line: `unborn HEAD symref-target:refs/heads/${defaultBranch}\n`,
        });
      }
    } else {
      if (headSha) {
        const symrefPart = symrefs ? ` symref-target:refs/heads/${defaultBranch}` : '';
        refCandidates.push({
          name: 'HEAD',
          line: `${headSha} HEAD${symrefPart}\n`,
        });
      }
      for (const [bName, bSha] of [...repo.branches.entries()].sort(([a], [b]) => a.localeCompare(b))) {
        refCandidates.push({
          name: `refs/heads/${bName}`,
          line: `${bSha} refs/heads/${bName}\n`,
        });
      }
      for (const [tRef, tSha] of [...repo.refs.entries()]
        .filter(([name]) => name.startsWith('refs/tags/'))
        .sort(([a], [b]) => a.localeCompare(b))) {
        const peeled = getPeeledSha(tSha);
        const peelPart = peel && peeled ? ` peeled:${peeled}` : '';
        refCandidates.push({
          name: tRef,
          line: `${tSha} ${tRef}${peelPart}\n`,
        });
      }
    }

    const filtered = prefixes.length > 0
      ? refCandidates.filter((r) => prefixes.some((pref) => r.name.startsWith(pref)))
      : refCandidates;

    const resLines: Array<string | 'flush'> = filtered.map((r) => r.line);
    resLines.push('flush');

    res.writeHead(200, {
      'content-type': 'application/x-git-upload-pack-result',
      'cache-control': 'no-cache, max-age=0, must-revalidate',
    });
    res.end(encodePktLines(resLines));
    return;
  }

  // Fetch command (v2 or v0)
  const isV2Fetch = firstLine.startsWith('command=fetch');

  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let deepen: number | undefined;
  let doneSent = false;

  for (const p of packets) {
    if (p.kind !== 'data') continue;
    const line = p.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) {
      const tokens = line.slice(5).trim().split(' ');
      wants.push(tokens[0]!);
    } else if (line.startsWith('have ')) {
      haves.push(line.slice(5).trim());
    } else if (line.startsWith('shallow ')) {
      shallow.push(line.slice(8).trim());
    } else if (line.startsWith('deepen ')) {
      deepen = parseInt(line.slice(7).trim(), 10);
    } else if (line === 'done') {
      doneSent = true;
    }
  }

  // A shallow client's haves include their trees, but not history beyond its boundary.
  const shallowSet = new Set(shallow);
  const haveOids = new Set<string>();
  for (const h of haves) {
    if (store.objects.has(h)) {
      collectReachable([h], (oid) => store.objects.get(oid), haveOids, shallowSet);
    }
  }

  let shallowReport: string[] = [];
  let unshallowReport: string[] = [];
  const visitedCommitDepths = new Map<string, number>();

  if (deepen !== undefined && deepen > 0) {
    const queue: Array<{ oid: string; depth: number }> = wants.map((w) => ({ oid: w, depth: 1 }));
    const newShallowSet = new Set<string>();
    while (queue.length > 0) {
      const { oid, depth: d } = queue.shift()!;
      if (visitedCommitDepths.has(oid)) continue;
      visitedCommitDepths.set(oid, d);
      const obj = store.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      if (d === deepen) {
        newShallowSet.add(oid);
        continue;
      }
      const commit = parseCommit(obj.data);
      for (const p of commit.parents) {
        queue.push({ oid: p, depth: d + 1 });
      }
    }
    shallowReport = [...newShallowSet];
    unshallowReport = shallow.filter((s) => visitedCommitDepths.has(s) && visitedCommitDepths.get(s)! < deepen);
  }

  const objectsToSend = new Map<string, { type: GitObjectType; data: Buffer }>();
  const walkQueue = [...wants];
  const walkVisited = new Set<string>();

  while (walkQueue.length > 0) {
    const oid = walkQueue.shift()!;
    if (walkVisited.has(oid)) continue;
    walkVisited.add(oid);

    const obj = store.objects.get(oid);
    if (!obj) continue;

    const alreadyHave = haveOids.has(oid);
    // Deepening must walk through a held tip to reach the newly requested parents.
    if (alreadyHave && (deepen === undefined || obj.type !== 'commit')) continue;
    if (!alreadyHave) objectsToSend.set(oid, obj);

    if (obj.type === 'commit') {
      const commit = parseCommit(obj.data);
      walkQueue.push(commit.tree);
      if (deepen !== undefined) {
        const d = visitedCommitDepths.get(oid);
        if (d !== undefined && d < deepen) {
          for (const p of commit.parents) walkQueue.push(p);
        }
      } else {
        if (!shallowSet.has(oid)) {
          for (const p of commit.parents) walkQueue.push(p);
        }
      }
    } else if (obj.type === 'tree') {
      const entries = parseTree(obj.data);
      for (const e of entries) {
        if (e.mode === '160000') continue;
        walkQueue.push(e.oid);
      }
    } else if (obj.type === 'tag') {
      const tag = parseTag(obj.data);
      walkQueue.push(tag.object);
    }
  }

  const packBuffer = writePack(objectsToSend.values());
  const sidebandPackets = encodeSideband(1, packBuffer);

  res.writeHead(200, {
    'content-type': 'application/x-git-upload-pack-result',
    'cache-control': 'no-cache, max-age=0, must-revalidate',
  });

  if (isV2Fetch) {
    // Protocol v2: when the client sends "done" the acknowledgments section is omitted and the
    // response goes straight to shallow-info/packfile. Sending it anyway makes real git abort with
    // "expected 'packfile', received 'acknowledgments'".
    if (!doneSent) {
      const matchingHaves = haves.filter((h) => store.objects.has(h));
      const ackLines: Array<string | 'delim'> = ['acknowledgments\n'];
      if (matchingHaves.length > 0) {
        for (const h of matchingHaves) ackLines.push(`ACK ${h}\n`);
        ackLines.push('ready\n');
      } else {
        ackLines.push('NAK\n');
        ackLines.push('ready\n');
      }
      ackLines.push('delim');
      res.write(encodePktLines(ackLines));
    }

    if (deepen !== undefined || shallowReport.length > 0 || unshallowReport.length > 0) {
      const shallowLines: Array<string | 'delim'> = ['shallow-info\n'];
      for (const s of shallowReport) shallowLines.push(`shallow ${s}\n`);
      for (const u of unshallowReport) shallowLines.push(`unshallow ${u}\n`);
      shallowLines.push('delim');
      res.write(encodePktLines(shallowLines));
    }

    res.write(encodePktLine('packfile\n'));
    for (const sp of sidebandPackets) res.write(sp);
    res.end(Buffer.from('0000', 'ascii'));
  } else {
    // Protocol V0
    if (shallowReport.length > 0 || unshallowReport.length > 0) {
      for (const s of shallowReport) res.write(encodePktLine(`shallow ${s}\n`));
      for (const u of unshallowReport) res.write(encodePktLine(`unshallow ${u}\n`));
    }
    const matchingHaves = haves.filter((h) => store.objects.has(h));
    if (matchingHaves.length > 0) {
      res.write(encodePktLine(`ACK ${matchingHaves[0]}\n`));
    } else {
      res.write(encodePktLine('NAK\n'));
    }
    for (const sp of sidebandPackets) res.write(sp);
    res.end(Buffer.from('0000', 'ascii'));
  }
}

async function handleReceivePack(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repository,
): Promise<void> {
  const rawBody = await readBodyBuffer(req);

  let offset = 0;
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let pushCaps: string[] = [];

  while (offset < rawBody.length) {
    if (offset + 4 > rawBody.length) break;
    const hex = rawBody.subarray(offset, offset + 4).toString('ascii');
    if (hex === '0000') {
      offset += 4;
      break;
    }
    const len = parseInt(hex, 16);
    if (isNaN(len) || len < 4 || offset + len > rawBody.length) {
      throw new Error(`invalid receive-pack header ${hex}`);
    }
    const payload = rawBody.subarray(offset + 4, offset + len);
    offset += len;
    let text = payload.toString('utf8').replace(/\n$/, '');
    if (commands.length === 0) {
      const nulIdx = text.indexOf('\0');
      if (nulIdx >= 0) {
        pushCaps = text.slice(nulIdx + 1).split(' ').filter(Boolean);
        text = text.slice(0, nulIdx);
      }
    }
    const tokens = text.trim().split(' ');
    if (tokens.length >= 3) {
      commands.push({ oldOid: tokens[0]!, newOid: tokens[1]!, ref: tokens[2]! });
    }
  }

  const packBytes = rawBody.subarray(offset);

  let unpackOk = true;
  let unpackDetail = 'ok';

  if (packBytes.length > 0) {
    try {
      const packResult = readPack(packBytes, {
        resolveBase: (oid) => store.objects.get(oid),
      });
      if (!packResult.checksumOk) {
        unpackOk = false;
        unpackDetail = 'pack checksum mismatch';
      } else {
        for (const [oid, obj] of packResult.objects) {
          if (obj.type === 'blob') store.saveBlobRaw(oid, obj.data);
          else if (obj.type === 'tree') store.saveTreeRaw(oid, obj.data);
          else if (obj.type === 'commit') store.saveCommitRaw(oid, obj.data);
          else if (obj.type === 'tag') store.saveTagRaw(oid, obj.data);
        }
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : String(err);
    }
  }

  interface RefResult {
    ref: string;
    ok: boolean;
    reason?: string;
  }
  const refResults: RefResult[] = [];

  for (const cmd of commands) {
    if (!unpackOk) {
      refResults.push({ ref: cmd.ref, ok: false, reason: 'unpack-failed' });
      continue;
    }
    if (cmd.newOid === ZERO_OID) {
      // Delete
      if (cmd.ref.startsWith('refs/heads/')) {
        const bName = cmd.ref.slice('refs/heads/'.length);
        repo.branches.delete(bName);
        repo.refs.delete(cmd.ref);
      } else if (cmd.ref.startsWith('refs/tags/')) {
        repo.refs.delete(cmd.ref);
      }
      refResults.push({ ref: cmd.ref, ok: true });
    } else if (cmd.oldOid === ZERO_OID) {
      // Create
      if (cmd.ref.startsWith('refs/heads/')) {
        const bName = cmd.ref.slice('refs/heads/'.length);
        repo.branches.set(bName, cmd.newOid);
        repo.refs.set(cmd.ref, cmd.newOid);
        if (!repo.branches.has(repo.default_branch)) {
          repo.default_branch = bName;
        }
      } else if (cmd.ref.startsWith('refs/tags/')) {
        repo.refs.set(cmd.ref, cmd.newOid);
      }
      refResults.push({ ref: cmd.ref, ok: true });
    } else {
      // Update: check fast-forward
      if (!isAncestor(cmd.oldOid, cmd.newOid)) {
        refResults.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      } else {
        if (cmd.ref.startsWith('refs/heads/')) {
          const bName = cmd.ref.slice('refs/heads/'.length);
          repo.branches.set(bName, cmd.newOid);
          repo.refs.set(cmd.ref, cmd.newOid);
        } else if (cmd.ref.startsWith('refs/tags/')) {
          repo.refs.set(cmd.ref, cmd.newOid);
        }
        refResults.push({ ref: cmd.ref, ok: true });
      }
    }
  }

  const reportParts: Buffer[] = [
    encodePktLine(`unpack ${unpackDetail}\n`),
    ...refResults.map((r) => encodePktLine(r.ok ? `ok ${r.ref}\n` : `ng ${r.ref} ${r.reason}\n`)),
    Buffer.from('0000', 'ascii'),
  ];
  const reportBytes = Buffer.concat(reportParts);

  res.writeHead(200, {
    'content-type': 'application/x-git-receive-pack-result',
    'cache-control': 'no-cache, max-age=0, must-revalidate',
  });

  const sideband = pushCaps.includes('side-band-64k');
  if (sideband) {
    const sidebandPackets = encodeSideband(1, reportBytes);
    for (const sp of sidebandPackets) res.write(sp);
    res.end(Buffer.from('0000', 'ascii'));
  } else {
    res.end(reportBytes);
  }
}

async function handleGitSmartHttp(
  req: IncomingMessage,
  res: ServerResponse,
  parsedUrl: URL,
  gitMatch: RegExpExecArray,
  reqId: string,
): Promise<void> {
  try {
    const owner = decodeURIComponent(gitMatch[1]!);
    const repoName = decodeURIComponent(gitMatch[2]!);
    const action = gitMatch[3]!;
    const method = req.method ?? 'GET';

    // Auth check
    const authHeader = req.headers.authorization;
    if (!authHeader || !/^Bearer\s+(.+)$/i.test(authHeader)) {
      res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('Bad credentials\n');
      return;
    }
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();
    if (token !== EXPECTED_TOKEN) {
      res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('Bad credentials\n');
      return;
    }

    // Repository lookup
    const repo = store.getRepo(owner, repoName);
    if (!repo) {
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('Repository not found\n');
      return;
    }

    if (action === 'info/refs' && method === 'GET') {
      const service = parsedUrl.searchParams.get('service');
      if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
        res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('Invalid or missing service\n');
        return;
      }
      handleInfoRefs(req, res, repo, service);
      return;
    }

    if (action === 'git-upload-pack' && method === 'POST') {
      await handleUploadPack(req, res, repo);
      return;
    }

    if (action === 'git-receive-pack' && method === 'POST') {
      await handleReceivePack(req, res, repo);
      return;
    }

    res.writeHead(405, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Method Not Allowed\n');
  } catch (err) {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`Bad Request: ${err instanceof Error ? err.message : String(err)}\n`);
  }
}

// ---------------------------------------------------------------------------------------------
// Main Server Creation

export function createApp(): Server {
  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const reqId = randomUUID();
    const parsedUrl = new URL(req.url ?? '/', 'http://entry');
    const path = parsedUrl.pathname;
    const method = req.method ?? 'GET';

    // Boot probe
    if (method === 'GET' && path === '/healthz') {
      sendJson(res, 200, { ok: true }, {}, reqId);
      return;
    }

    if (path === '/api/graphql') {
      await handleGraphQL(req, res, reqId);
      return;
    }

    // Git Smart HTTP routes
    const gitMatch = /^\/([^/]+)\/([^/]+?)(?:\.git)?\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(path);
    if (gitMatch) {
      await handleGitSmartHttp(req, res, parsedUrl, gitMatch, reqId);
      return;
    }

    // Only /api/v3/* and /api/v3 are handled under REST v3
    if (!path.startsWith('/api/v3')) {
      sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
      return;
    }

    // Auth check for every /api/v3 route
    const authHeader = req.headers.authorization;
    if (!authHeader || !/^Bearer\s+(.+)$/i.test(authHeader)) {
      sendJson(res, 401, { message: 'Bad credentials' }, {}, reqId);
      return;
    }
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();
    if (token !== EXPECTED_TOKEN) {
      sendJson(res, 401, { message: 'Bad credentials' }, {}, reqId);
      return;
    }

    // Parse JSON request body if present
    let rawBody = '';
    let body: any = {};
    if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
      try {
        rawBody = await readBody(req);
        if (rawBody.trim() !== '') {
          body = JSON.parse(rawBody);
        }
      } catch {
        sendJson(res, 400, { message: 'Problems parsing JSON' }, {}, reqId);
        return;
      }
    }

    // Authenticated viewer
    const viewer = store.users.get('adaiversen')!;

    // -----------------------------------------------------------------------------------------
    // Routes

    // GET /api/v3/ or GET /api/v3
    if ((path === '/api/v3' || path === '/api/v3/') && method === 'GET') {
      sendJson(
        res,
        200,
        {
          current_user_url: '/api/v3/user',
          current_user_authorizations_html_url: '/api/v3/user',
          rate_limit_url: '/api/v3/rate_limit',
          repository_url: '/api/v3/repos/{owner}/{repo}',
        },
        { 'x-oauth-scopes': 'repo, read:org' },
        reqId,
      );
      return;
    }

    // GET /api/v3/meta
    if (path === '/api/v3/meta' && method === 'GET') {
      sendJson(res, 200, { installed_version: '1.0.0' }, {}, reqId);
      return;
    }

    // GET /api/v3/rate_limit
    if (path === '/api/v3/rate_limit' && method === 'GET') {
      sendJson(
        res,
        200,
        {
          resources: {
            core: { limit: 5000, remaining: 4999, reset: 1700000000, used: 1 },
            graphql: { limit: 5000, remaining: 5000, reset: 1700000000, used: 0 },
          },
          rate: { limit: 5000, remaining: 4999, reset: 1700000000, used: 1 },
        },
        {},
        reqId,
      );
      return;
    }

    // GET /api/v3/user
    if (path === '/api/v3/user' && method === 'GET') {
      sendJson(res, 200, { ...viewer }, {}, reqId);
      return;
    }

    // GET /api/v3/user/repos
    if (path === '/api/v3/user/repos' && method === 'GET') {
      const viewerRepos = store.userRepoList.filter((r) => r.owner.toLowerCase() === viewer.login.toLowerCase());
      paginate(req, res, viewerRepos.map(repoJson), reqId);
      return;
    }

    // POST /api/v3/user/repos
    if (path === '/api/v3/user/repos' && method === 'POST') {
      const name = String(body.name || '').trim();
      if (!name) {
        sendJson(res, 422, { message: 'Repository name required' }, {}, reqId);
        return;
      }
      if (store.getRepo(viewer.login, name)) {
        sendJson(res, 422, { message: 'Repository already exists' }, {}, reqId);
        return;
      }
      const newRepo: Repository = {
        id: store.nextRepoId++,
        owner: viewer.login,
        name,
        description: body.description || '',
        private: body.private ?? true,
        default_branch: body.default_branch || 'main',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        branches: new Map(),
        refs: new Map(),
        labels: new Map(),
        issues: new Map(),
        issueCounter: 0,
        pulls: new Map(),
        pullCounter: 0,
        comments: new Map(),
        commentCounter: 0,
      };
      store.repos.set(store.repoKey(newRepo.owner, newRepo.name), newRepo);
      store.userRepoList.push(newRepo);
      sendJson(res, 201, repoJson(newRepo), {}, reqId);
      return;
    }

    // GET /api/v3/users/:user/repos
    const usersReposMatch = /^\/api\/v3\/users\/([^/]+)\/repos\/?$/.exec(path);
    if (usersReposMatch && method === 'GET') {
      const user = decodeURIComponent(usersReposMatch[1]!);
      const list = store.userRepoList.filter((r) => r.owner.toLowerCase() === user.toLowerCase());
      paginate(req, res, list.map(repoJson), reqId);
      return;
    }

    // GET /api/v3/orgs/:org/repos
    const orgsReposMatch = /^\/api\/v3\/orgs\/([^/]+)\/repos\/?$/.exec(path);
    if (orgsReposMatch && method === 'GET') {
      const org = decodeURIComponent(orgsReposMatch[1]!);
      const list = store.userRepoList.filter((r) => r.owner.toLowerCase() === org.toLowerCase());
      paginate(req, res, list.map(repoJson), reqId);
      return;
    }

    // -----------------------------------------------------------------------------------------
    // Routes under /api/v3/repos/:owner/:repo/...

    const repoPathMatch = /^\/api\/v3\/repos\/([^/]+)\/([^/]+)(?:\/(.*))?$/.exec(path);
    if (!repoPathMatch) {
      sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
      return;
    }

    const repoOwner = decodeURIComponent(repoPathMatch[1]!);
    const repoName = decodeURIComponent(repoPathMatch[2]!);
    const subPath = repoPathMatch[3] ? repoPathMatch[3].replace(/\/+$/, '') : '';

    const repo = store.getRepo(repoOwner, repoName);

    // Repository root: GET /api/v3/repos/:owner/:repo
    if (!subPath) {
      if (!repo) {
        sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, repoJson(repo), {}, reqId);
        return;
      }
      if (method === 'PATCH') {
        if (body.description !== undefined) repo.description = String(body.description);
        if (body.default_branch !== undefined) repo.default_branch = String(body.default_branch);
        if (body.private !== undefined) repo.private = Boolean(body.private);
        if (body.name !== undefined) {
          store.repos.delete(store.repoKey(repo.owner, repo.name));
          repo.name = String(body.name);
          store.repos.set(store.repoKey(repo.owner, repo.name), repo);
        }
        repo.updated_at = new Date().toISOString();
        sendJson(res, 200, repoJson(repo), {}, reqId);
        return;
      }
      if (method === 'DELETE') {
        store.repos.delete(store.repoKey(repo.owner, repo.name));
        const idx = store.userRepoList.findIndex((r) => r.id === repo.id);
        if (idx >= 0) store.userRepoList.splice(idx, 1);
        sendEmpty(res, 204, {}, reqId);
        return;
      }
      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    // All other repo sub-resources require the repo to exist
    if (!repo) {
      sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
      return;
    }

    // -----------------------------------------------------------------------------------------
    // Branches: /branches and /branches/:branch

    if (subPath === 'branches' && method === 'GET') {
      const branchesList = Array.from(repo.branches.entries()).map(([name, sha]) => ({
        name,
        commit: { sha },
        protected: false,
      }));
      paginate(req, res, branchesList, reqId);
      return;
    }

    const branchDetailMatch = /^branches\/(.+)$/.exec(subPath);
    if (branchDetailMatch && method === 'GET') {
      const branchName = decodeURIComponent(branchDetailMatch[1]!);
      const sha = repo.branches.get(branchName);
      if (!sha) {
        sendJson(res, 404, { message: 'Branch not found' }, {}, reqId);
        return;
      }
      sendJson(res, 200, { name: branchName, commit: { sha }, protected: false }, {}, reqId);
      return;
    }

    // -----------------------------------------------------------------------------------------
    // Commits: /commits and /commits/:sha

    if (subPath === 'commits' && method === 'GET') {
      const targetSha = parsedUrl.searchParams.get('sha') || repo.default_branch;
      let startSha = repo.branches.get(targetSha) || repo.refs.get(targetSha);
      if (!startSha && store.commits.has(targetSha)) {
        startSha = targetSha;
      }
      if (!startSha) {
        paginate(req, res, [], reqId);
        return;
      }

      // Collect reachable commits in topological/reverse-chronological order
      const reachable: GitCommit[] = [];
      const visited = new Set<string>();
      const queue = [startSha];
      while (queue.length > 0) {
        const sha = queue.shift()!;
        if (visited.has(sha)) continue;
        visited.add(sha);
        const commit = store.commits.get(sha);
        if (commit) {
          reachable.push(commit);
          for (const p of commit.parents) {
            queue.push(p);
          }
        }
      }

      const commitList = reachable.map((c) => ({
        sha: c.sha,
        commit: {
          message: c.message,
          author: c.author,
          committer: c.committer,
          tree: { sha: c.tree },
        },
        parents: c.parents.map((p) => ({ sha: p })),
      }));
      paginate(req, res, commitList, reqId);
      return;
    }

    const commitDetailMatch = /^commits\/([0-9a-fA-F]{40})$/.exec(subPath);
    if (commitDetailMatch && method === 'GET') {
      const sha = commitDetailMatch[1]!;
      const commit = store.commits.get(sha);
      if (!commit) {
        sendJson(res, 404, { message: 'Commit not found' }, {}, reqId);
        return;
      }
      sendJson(
        res,
        200,
        {
          sha: commit.sha,
          commit: {
            message: commit.message,
            author: commit.author,
            committer: commit.committer,
            tree: { sha: commit.tree },
          },
          parents: commit.parents.map((p) => ({ sha: p })),
          tree: { sha: commit.tree },
        },
        {},
        reqId,
      );
      return;
    }

    // -----------------------------------------------------------------------------------------
    // Contents: /contents/:path*

    const contentsMatch = /^contents(?:\/(.*))?$/.exec(subPath);
    if (contentsMatch) {
      const filePath = contentsMatch[1] ? decodeURIComponent(contentsMatch[1]) : '';
      const ref = parsedUrl.searchParams.get('ref') || repo.default_branch;
      let targetCommitSha = repo.branches.get(ref) || repo.refs.get(ref);
      if (!targetCommitSha && store.commits.has(ref)) {
        targetCommitSha = ref;
      }

      if (method === 'GET') {
        if (!targetCommitSha) {
          sendJson(res, 404, { message: 'This repository is empty.' }, {}, reqId);
          return;
        }
        const commit = store.commits.get(targetCommitSha);
        if (!commit) {
          sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
          return;
        }

        const files = store.flattenTree(commit.tree);

        // Directory listing (empty path or directory path)
        if (filePath === '' || !files.has(filePath)) {
          // Check if it's a directory
          const dirPrefix = filePath === '' ? '' : `${filePath}/`;
          const dirEntries = new Map<string, { type: 'file' | 'dir'; name: string; path: string; sha: string; size: number }>();

          for (const [fullPath, entry] of files) {
            if (dirPrefix === '' || fullPath.startsWith(dirPrefix)) {
              const remainder = dirPrefix === '' ? fullPath : fullPath.slice(dirPrefix.length);
              const slashIdx = remainder.indexOf('/');
              if (slashIdx === -1) {
                // Direct file child
                const blob = store.blobs.get(entry.sha);
                dirEntries.set(remainder, {
                  type: 'file',
                  name: remainder,
                  path: fullPath,
                  sha: entry.sha,
                  size: blob?.size || 0,
                });
              } else {
                // Subdirectory child
                const dirName = remainder.slice(0, slashIdx);
                if (!dirEntries.has(dirName)) {
                  dirEntries.set(dirName, {
                    type: 'dir',
                    name: dirName,
                    path: dirPrefix ? `${dirPrefix}${dirName}` : dirName,
                    sha: '0000000000000000000000000000000000000000',
                    size: 0,
                  });
                }
              }
            }
          }

          if (dirEntries.size > 0 || filePath === '') {
            sendJson(res, 200, Array.from(dirEntries.values()), {}, reqId);
            return;
          }

          sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
          return;
        }

        // Single file
        const entry = files.get(filePath)!;
        const blob = store.blobs.get(entry.sha);
        const contentStr = blob ? blob.data.toString('base64') : '';
        const baseName = filePath.slice(filePath.lastIndexOf('/') + 1);
        sendJson(
          res,
          200,
          {
            type: 'file',
            encoding: 'base64',
            content: contentStr,
            sha: entry.sha,
            size: blob?.size || 0,
            name: baseName,
            path: filePath,
          },
          {},
          reqId,
        );
        return;
      }

      if (method === 'PUT') {
        const branchName = body.branch || repo.default_branch;
        const commitMsg = body.message || 'update file';
        const contentBase64 = String(body.content || '');
        const fileBytes = Buffer.from(contentBase64.replace(/[\r\n\s]/g, ''), 'base64');
        const blob = store.saveBlob(fileBytes);

        let parentCommitSha = repo.branches.get(branchName);
        let currentFiles = parentCommitSha ? store.getFilesAtCommit(parentCommitSha) : new Map<string, { sha: string; mode: string }>();

        const existing = currentFiles.get(filePath);
        if (existing) {
          // File update: check stale sha
          if (body.sha && body.sha.toLowerCase() !== existing.sha.toLowerCase()) {
            sendJson(res, 409, { message: 'Conflict: sha does not match' }, {}, reqId);
            return;
          }
        }

        const isNew = !existing;
        currentFiles.set(filePath, { sha: blob.sha, mode: '100644' });
        const newTreeSha = store.buildTreeFromFiles(currentFiles);
        const parents = parentCommitSha ? [parentCommitSha] : [];
        const newCommit = store.saveCommit(
          newTreeSha,
          parents,
          commitMsg,
          { name: viewer.name, email: viewer.email, date: new Date().toISOString() },
          { name: viewer.name, email: viewer.email, date: new Date().toISOString() },
        );

        repo.branches.set(branchName, newCommit.sha);
        repo.refs.set(`refs/heads/${branchName}`, newCommit.sha);

        const baseName = filePath.slice(filePath.lastIndexOf('/') + 1);
        const status = isNew && !parentCommitSha ? 201 : isNew ? 201 : 200;
        sendJson(
          res,
          status,
          {
            content: {
              name: baseName,
              path: filePath,
              sha: blob.sha,
              size: blob.size,
              encoding: 'base64',
              type: 'file',
            },
            commit: {
              sha: newCommit.sha,
            },
          },
          {},
          reqId,
        );
        return;
      }

      if (method === 'DELETE') {
        const branchName = body.branch || repo.default_branch;
        const commitMsg = body.message || 'delete file';
        const parentCommitSha = repo.branches.get(branchName);
        if (!parentCommitSha) {
          sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
          return;
        }

        const currentFiles = store.getFilesAtCommit(parentCommitSha);
        const existing = currentFiles.get(filePath);
        if (!existing) {
          sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
          return;
        }

        if (body.sha && body.sha.toLowerCase() !== existing.sha.toLowerCase()) {
          sendJson(res, 409, { message: 'Conflict: sha does not match' }, {}, reqId);
          return;
        }

        currentFiles.delete(filePath);
        const newTreeSha = store.buildTreeFromFiles(currentFiles);
        const newCommit = store.saveCommit(
          newTreeSha,
          [parentCommitSha],
          commitMsg,
          { name: viewer.name, email: viewer.email, date: new Date().toISOString() },
          { name: viewer.name, email: viewer.email, date: new Date().toISOString() },
        );

        repo.branches.set(branchName, newCommit.sha);
        repo.refs.set(`refs/heads/${branchName}`, newCommit.sha);

        sendJson(
          res,
          200,
          {
            commit: { sha: newCommit.sha },
            content: null,
          },
          {},
          reqId,
        );
        return;
      }

      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    // -----------------------------------------------------------------------------------------
    // Git Refs: /git/refs and /git/refs/:ref*

    if (subPath === 'git/refs' && method === 'POST') {
      const ref = String(body.ref || '');
      const sha = String(body.sha || '');
      if (!ref || !sha) {
        sendJson(res, 422, { message: 'ref and sha required' }, {}, reqId);
        return;
      }
      if (repo.refs.has(ref)) {
        sendJson(res, 422, { message: 'Reference already exists' }, {}, reqId);
        return;
      }
      repo.refs.set(ref, sha);
      if (ref.startsWith('refs/heads/')) {
        const bName = ref.slice('refs/heads/'.length);
        repo.branches.set(bName, sha);
      }
      sendJson(
        res,
        201,
        {
          ref,
          node_id: randomUUID(),
          url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${ref}`,
          object: { sha, type: 'commit', url: `/api/v3/repos/${repo.owner}/${repo.name}/git/commits/${sha}` },
        },
        {},
        reqId,
      );
      return;
    }

    const gitRefMatch = /^git\/refs\/(.+)$/.exec(subPath);
    if (gitRefMatch) {
      const refQuery = decodeURIComponent(gitRefMatch[1]!);
      const fullRef = refQuery.startsWith('refs/') ? refQuery : `refs/${refQuery}`;

      if (method === 'GET') {
        const exactSha = repo.refs.get(fullRef) || repo.refs.get(refQuery);
        if (exactSha) {
          sendJson(
            res,
            200,
            {
              ref: fullRef,
              node_id: randomUUID(),
              url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${fullRef}`,
              object: { sha: exactSha, type: 'commit' },
            },
            {},
            reqId,
          );
          return;
        }

        // Sub-prefix matching
        const matching: any[] = [];
        for (const [r, s] of repo.refs) {
          if (r.startsWith(fullRef) || r.startsWith(`refs/${refQuery}`)) {
            matching.push({
              ref: r,
              node_id: randomUUID(),
              url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${r}`,
              object: { sha: s, type: 'commit' },
            });
          }
        }
        if (matching.length > 0) {
          sendJson(res, 200, matching, {}, reqId);
          return;
        }

        sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
        return;
      }

      if (method === 'PATCH') {
        const sha = String(body.sha || '');
        if (!repo.refs.has(fullRef)) {
          sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
          return;
        }
        repo.refs.set(fullRef, sha);
        if (fullRef.startsWith('refs/heads/')) {
          repo.branches.set(fullRef.slice('refs/heads/'.length), sha);
        }
        sendJson(
          res,
          200,
          {
            ref: fullRef,
            node_id: randomUUID(),
            url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${fullRef}`,
            object: { sha, type: 'commit' },
          },
          {},
          reqId,
        );
        return;
      }

      if (method === 'DELETE') {
        if (!repo.refs.has(fullRef)) {
          sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
          return;
        }
        repo.refs.delete(fullRef);
        if (fullRef.startsWith('refs/heads/')) {
          repo.branches.delete(fullRef.slice('refs/heads/'.length));
        }
        sendEmpty(res, 204, {}, reqId);
        return;
      }

      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    // -----------------------------------------------------------------------------------------
    // Git Commits: /git/commits and /git/commits/:sha

    if (subPath === 'git/commits' && method === 'POST') {
      const tree = String(body.tree || '');
      const message = String(body.message || '');
      const parents = Array.isArray(body.parents) ? body.parents : [];
      const commit = store.saveCommit(
        tree,
        parents,
        message,
        body.author || { name: viewer.name, email: viewer.email, date: new Date().toISOString() },
        body.committer || { name: viewer.name, email: viewer.email, date: new Date().toISOString() },
      );
      sendJson(
        res,
        201,
        {
          sha: commit.sha,
          tree: { sha: commit.tree },
          parents: commit.parents.map((p) => ({ sha: p })),
          message: commit.message,
          author: commit.author,
          committer: commit.committer,
        },
        {},
        reqId,
      );
      return;
    }

    const gitCommitMatch = /^git\/commits\/([0-9a-fA-F]{40})$/.exec(subPath);
    if (gitCommitMatch && method === 'GET') {
      const commit = store.commits.get(gitCommitMatch[1]!);
      if (!commit) {
        sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
        return;
      }
      sendJson(
        res,
        200,
        {
          sha: commit.sha,
          tree: { sha: commit.tree },
          parents: commit.parents.map((p) => ({ sha: p })),
          message: commit.message,
          author: commit.author,
          committer: commit.committer,
        },
        {},
        reqId,
      );
      return;
    }

    // -----------------------------------------------------------------------------------------
    // Git Trees: /git/trees and /git/trees/:sha

    if (subPath === 'git/trees' && method === 'POST') {
      const baseTreeSha = body.base_tree ? String(body.base_tree) : undefined;
      const files = baseTreeSha ? store.flattenTree(baseTreeSha) : new Map<string, { sha: string; mode: string }>();

      if (Array.isArray(body.tree)) {
        for (const item of body.tree) {
          if (item.content !== undefined) {
            const blob = store.saveBlob(Buffer.from(String(item.content), 'utf-8'));
            files.set(item.path, { sha: blob.sha, mode: item.mode || '100644' });
          } else if (item.sha) {
            files.set(item.path, { sha: item.sha, mode: item.mode || '100644' });
          }
        }
      }
      const newTreeSha = store.buildTreeFromFiles(files);
      const treeObj = store.trees.get(newTreeSha)!;
      sendJson(
        res,
        201,
        {
          sha: newTreeSha,
          tree: treeObj.entries.map((e) => ({
            path: e.name,
            mode: e.mode,
            type: e.type,
            sha: e.sha,
          })),
        },
        {},
        reqId,
      );
      return;
    }

    const gitTreeMatch = /^git\/trees\/([0-9a-fA-F]{40})$/.exec(subPath);
    if (gitTreeMatch && method === 'GET') {
      const tree = store.trees.get(gitTreeMatch[1]!);
      if (!tree) {
        sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
        return;
      }
      sendJson(
        res,
        200,
        {
          sha: tree.sha,
          tree: tree.entries.map((e) => ({
            path: e.name,
            mode: e.mode,
            type: e.type,
            sha: e.sha,
          })),
        },
        {},
        reqId,
      );
      return;
    }

    // -----------------------------------------------------------------------------------------
    // Git Blobs: /git/blobs and /git/blobs/:sha

    if (subPath === 'git/blobs' && method === 'POST') {
      const encoding = body.encoding === 'base64' ? 'base64' : 'utf-8';
      const content = String(body.content || '');
      const data = Buffer.from(content, encoding as BufferEncoding);
      const blob = store.saveBlob(data);
      sendJson(res, 201, { sha: blob.sha }, {}, reqId);
      return;
    }

    const gitBlobMatch = /^git\/blobs\/([0-9a-fA-F]{40})$/.exec(subPath);
    if (gitBlobMatch && method === 'GET') {
      const blob = store.blobs.get(gitBlobMatch[1]!);
      if (!blob) {
        sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
        return;
      }
      sendJson(
        res,
        200,
        {
          sha: blob.sha,
          size: blob.size,
          content: blob.data.toString('base64'),
          encoding: 'base64',
        },
        {},
        reqId,
      );
      return;
    }

    // -----------------------------------------------------------------------------------------
    // Labels: /labels and /labels/:name

    if (subPath === 'labels') {
      if (method === 'GET') {
        const labelsList = Array.from(repo.labels.values());
        paginate(req, res, labelsList, reqId);
        return;
      }
      if (method === 'POST') {
        const name = String(body.name || '').trim();
        if (!name) {
          sendJson(res, 422, { message: 'Label name required' }, {}, reqId);
          return;
        }
        const label: Label = {
          id: store.nextLabelId++,
          name,
          color: String(body.color || 'ededed'),
          description: String(body.description || ''),
        };
        repo.labels.set(name, label);
        sendJson(res, 201, label, {}, reqId);
        return;
      }
      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    const labelDetailMatch = /^labels\/(.+)$/.exec(subPath);
    if (labelDetailMatch) {
      const labelName = decodeURIComponent(labelDetailMatch[1]!);
      if (method === 'DELETE') {
        repo.labels.delete(labelName);
        sendEmpty(res, 204, {}, reqId);
        return;
      }
      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    // -----------------------------------------------------------------------------------------
    // Issues: /issues, /issues/:number, /issues/:number/comments, /issues/comments/:id

    if (subPath === 'issues') {
      if (method === 'GET') {
        const state = parsedUrl.searchParams.get('state') || 'open';
        const sort = parsedUrl.searchParams.get('sort') || 'created';
        const direction = parsedUrl.searchParams.get('direction') || 'desc';

        let list = Array.from(repo.issues.values());
        if (state !== 'all') {
          list = list.filter((i) => i.state === state);
        }

        list.sort((a, b) => {
          if (sort === 'created') {
            return direction === 'asc' ? a.number - b.number : b.number - a.number;
          }
          return 0;
        });

        paginate(req, res, list.map((i) => issueJson(i, repo)), reqId);
        return;
      }

      if (method === 'POST') {
        const title = String(body.title || '');
        const issueBody = String(body.body || '');
        const labelsInput: string[] = Array.isArray(body.labels) ? body.labels.map(String) : [];

        // Validate that all labels exist in the repo
        for (const lName of labelsInput) {
          if (!repo.labels.has(lName)) {
            sendJson(res, 422, { message: `Label ${lName} does not exist` }, {}, reqId);
            return;
          }
        }

        const issue = createIssueRecord(repo, viewer, title, issueBody, labelsInput);
        sendJson(res, 201, issueJson(issue, repo), {}, reqId);
        return;
      }

      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    const issueNumMatch = /^issues\/(\d+)$/.exec(subPath);
    if (issueNumMatch) {
      const issueNum = parseInt(issueNumMatch[1]!, 10);
      const issue = repo.issues.get(issueNum);
      if (!issue) {
        sendJson(res, 404, { message: 'Issue not found' }, {}, reqId);
        return;
      }

      if (method === 'GET') {
        sendJson(res, 200, issueJson(issue, repo), {}, reqId);
        return;
      }

      if (method === 'PATCH') {
        if (body.title !== undefined) issue.title = String(body.title);
        if (body.body !== undefined) issue.body = String(body.body);
        if (body.state !== undefined) {
          if (body.state === 'open' || body.state === 'closed') {
            issue.state = body.state;
          }
        }
        if (Array.isArray(body.labels)) {
          issue.labels = body.labels.map(String);
        }
        issue.updated_at = new Date().toISOString();
        sendJson(res, 200, issueJson(issue, repo), {}, reqId);
        return;
      }

      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    // Issue Comments: /issues/:number/comments
    const issueCommentsMatch = /^issues\/(\d+)\/comments$/.exec(subPath);
    if (issueCommentsMatch) {
      const issueNum = parseInt(issueCommentsMatch[1]!, 10);
      const issue = repo.issues.get(issueNum);
      if (!issue) {
        sendJson(res, 404, { message: 'Issue not found' }, {}, reqId);
        return;
      }

      if (method === 'GET') {
        const comments = Array.from(repo.comments.values()).filter((c) => c.issue_number === issueNum);
        paginate(req, res, comments, reqId);
        return;
      }

      if (method === 'POST') {
        const commentBody = String(body.body || '');
        const comment = createCommentRecord(repo, viewer, issue, commentBody);
        sendJson(res, 201, comment, {}, reqId);
        return;
      }

      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    // Comments direct: /issues/comments/:id
    const commentDetailMatch = /^issues\/comments\/(\d+)$/.exec(subPath);
    if (commentDetailMatch) {
      const commentId = parseInt(commentDetailMatch[1]!, 10);
      const comment = repo.comments.get(commentId);
      if (!comment) {
        sendJson(res, 404, { message: 'Comment not found' }, {}, reqId);
        return;
      }

      if (method === 'GET') {
        sendJson(res, 200, comment, {}, reqId);
        return;
      }

      if (method === 'PATCH') {
        if (body.body !== undefined) comment.body = String(body.body);
        comment.updated_at = new Date().toISOString();
        sendJson(res, 200, comment, {}, reqId);
        return;
      }

      if (method === 'DELETE') {
        repo.comments.delete(commentId);
        const issue = repo.issues.get(comment.issue_number);
        if (issue && issue.comments > 0) issue.comments--;
        sendEmpty(res, 204, {}, reqId);
        return;
      }

      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    // Issue Labels: /issues/:number/labels
    const issueLabelsMatch = /^issues\/(\d+)\/labels(?:\/(.+))?$/.exec(subPath);
    if (issueLabelsMatch) {
      const issueNum = parseInt(issueLabelsMatch[1]!, 10);
      const issue = repo.issues.get(issueNum);
      if (!issue) {
        sendJson(res, 404, { message: 'Issue not found' }, {}, reqId);
        return;
      }

      const labelName = issueLabelsMatch[2] ? decodeURIComponent(issueLabelsMatch[2]) : undefined;

      if (!labelName) {
        if (method === 'GET') {
          const labels = issue.labels.map((lName) => {
            const l = repo.labels.get(lName);
            return { id: l?.id || 1, name: lName, color: l?.color || 'ededed' };
          });
          sendJson(res, 200, labels, {}, reqId);
          return;
        }

        if (method === 'POST') {
          const toAdd: string[] = Array.isArray(body)
            ? body.map(String)
            : Array.isArray(body.labels)
              ? body.labels.map(String)
              : [];
          for (const name of toAdd) {
            if (!issue.labels.includes(name)) issue.labels.push(name);
          }
          const labels = issue.labels.map((lName) => {
            const l = repo.labels.get(lName);
            return { id: l?.id || 1, name: lName, color: l?.color || 'ededed' };
          });
          sendJson(res, 200, labels, {}, reqId);
          return;
        }
      } else {
        if (method === 'DELETE') {
          issue.labels = issue.labels.filter((l) => l !== labelName);
          const labels = issue.labels.map((lName) => {
            const l = repo.labels.get(lName);
            return { id: l?.id || 1, name: lName, color: l?.color || 'ededed' };
          });
          sendJson(res, 200, labels, {}, reqId);
          return;
        }
      }

      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    // -----------------------------------------------------------------------------------------
    // Pull Requests: /pulls, /pulls/:number, /pulls/:number/files, /pulls/:number/merge

    if (subPath === 'pulls') {
      if (method === 'GET') {
        const state = parsedUrl.searchParams.get('state') || 'open';
        let list = Array.from(repo.pulls.values());
        if (state !== 'all') {
          list = list.filter((p) => p.state === state);
        }
        list.sort((a, b) => b.number - a.number);
        paginate(req, res, list.map((p) => pullJson(p, repo)), reqId);
        return;
      }

      if (method === 'POST') {
        const title = String(body.title || '');
        const pullBody = String(body.body || '');
        const head = String(body.head || '');
        const base = String(body.base || '');

        const pull = createPullRecord(repo, viewer, title, pullBody, head, base);
        if (!pull) {
          sendJson(res, 422, { message: 'Invalid head or base branch' }, {}, reqId);
          return;
        }

        sendJson(res, 201, pullJson(pull, repo), {}, reqId);
        return;
      }

      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    const pullNumMatch = /^pulls\/(\d+)$/.exec(subPath);
    if (pullNumMatch) {
      const pullNum = parseInt(pullNumMatch[1]!, 10);
      const pull = repo.pulls.get(pullNum);
      if (!pull) {
        sendJson(res, 404, { message: 'Pull request not found' }, {}, reqId);
        return;
      }

      if (method === 'GET') {
        sendJson(res, 200, pullJson(pull, repo), {}, reqId);
        return;
      }

      if (method === 'PATCH') {
        if (body.title !== undefined) pull.title = String(body.title);
        if (body.body !== undefined) pull.body = String(body.body);
        if (body.state !== undefined && (body.state === 'open' || body.state === 'closed')) {
          pull.state = body.state;
        }
        pull.updated_at = new Date().toISOString();
        sendJson(res, 200, pullJson(pull, repo), {}, reqId);
        return;
      }

      sendJson(res, 405, { message: 'Method Not Allowed' }, {}, reqId);
      return;
    }

    const pullFilesMatch = /^pulls\/(\d+)\/files$/.exec(subPath);
    if (pullFilesMatch && method === 'GET') {
      const pullNum = parseInt(pullFilesMatch[1]!, 10);
      const pull = repo.pulls.get(pullNum);
      if (!pull) {
        sendJson(res, 404, { message: 'Pull request not found' }, {}, reqId);
        return;
      }

      const headSha = repo.branches.get(pull.head.ref) || pull.head.sha;
      const baseSha = repo.branches.get(pull.base.ref) || pull.base.sha;
      const headFiles = store.getFilesAtCommit(headSha);
      const baseFiles = store.getFilesAtCommit(baseSha);

      const filesList: any[] = [];

      for (const [fPath, headEntry] of headFiles) {
        const baseEntry = baseFiles.get(fPath);
        if (!baseEntry) {
          const blob = store.blobs.get(headEntry.sha);
          const lines = blob && blob.size > 0 ? blob.data.toString('utf-8').split('\n').length : 1;
          filesList.push({
            filename: fPath,
            status: 'added',
            additions: Math.max(1, lines),
            deletions: 0,
            changes: Math.max(1, lines),
          });
        } else if (baseEntry.sha !== headEntry.sha) {
          const headBlob = store.blobs.get(headEntry.sha);
          const baseBlob = store.blobs.get(baseEntry.sha);
          const headLines = headBlob ? headBlob.data.toString('utf-8').split('\n').length : 1;
          const baseLines = baseBlob ? baseBlob.data.toString('utf-8').split('\n').length : 1;
          filesList.push({
            filename: fPath,
            status: 'modified',
            additions: Math.max(1, headLines),
            deletions: Math.max(1, baseLines),
            changes: Math.max(1, headLines) + Math.max(1, baseLines),
          });
        }
      }

      for (const [fPath, baseEntry] of baseFiles) {
        if (!headFiles.has(fPath)) {
          const blob = store.blobs.get(baseEntry.sha);
          const lines = blob && blob.size > 0 ? blob.data.toString('utf-8').split('\n').length : 1;
          filesList.push({
            filename: fPath,
            status: 'removed',
            additions: 0,
            deletions: Math.max(1, lines),
            changes: Math.max(1, lines),
          });
        }
      }

      paginate(req, res, filesList, reqId);
      return;
    }

    const pullMergeMatch = /^pulls\/(\d+)\/merge$/.exec(subPath);
    if (pullMergeMatch && method === 'PUT') {
      const pullNum = parseInt(pullMergeMatch[1]!, 10);
      const pull = repo.pulls.get(pullNum);
      if (!pull) {
        sendJson(res, 404, { message: 'Pull request not found' }, {}, reqId);
        return;
      }
      if (pull.state !== 'open' || pull.merged) {
        sendJson(res, 405, { message: 'Pull request is not open' }, {}, reqId);
        return;
      }

      const mergeCommit = mergePullRecord(repo, pull, viewer, body.commit_title);
      if (!mergeCommit) {
        sendJson(res, 405, { message: 'Pull request cannot be merged due to conflict' }, {}, reqId);
        return;
      }

      sendJson(
        res,
        200,
        {
          sha: mergeCommit.sha,
          merged: true,
          message: 'Pull Request successfully merged',
        },
        {},
        reqId,
      );
      return;
    }

    // Default 404 for any unmatched route under /api/v3
    sendJson(res, 404, { message: 'Not Found' }, {}, reqId);
  });
}
