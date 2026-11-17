// GitHub REST v3 server implementation for github-core-clone-01.
// stdlib only (node:http, node:crypto), TypeScript that Node 22 strips.

import { createHash, randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

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
// In-Memory Data Store

class ForgeStore {
  users = new Map<string, User>();
  repos = new Map<string, Repository>(); // `${owner.toLowerCase()}/${name.toLowerCase()}`
  userRepoList: Repository[] = []; // List of all repos for pagination order
  blobs = new Map<string, GitBlob>();
  trees = new Map<string, GitTree>();
  commits = new Map<string, GitCommit>();

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
    return commit;
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

        const issueNum = ++repo.issueCounter;
        const now = new Date().toISOString();
        const issue: Issue = {
          number: issueNum,
          title,
          body: issueBody,
          state: 'open',
          labels: labelsInput,
          comments: 0,
          created_at: now,
          updated_at: now,
          user: { login: viewer.login, id: viewer.id },
        };
        repo.issues.set(issueNum, issue);
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
        const commentId = store.nextCommentId++;
        const now = new Date().toISOString();
        const comment: Comment = {
          id: commentId,
          body: commentBody,
          issue_number: issueNum,
          created_at: now,
          updated_at: now,
          user: { login: viewer.login, id: viewer.id },
        };
        repo.comments.set(commentId, comment);
        issue.comments++;
        issue.updated_at = now;
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

        const headSha = repo.branches.get(head) || repo.refs.get(head);
        const baseSha = repo.branches.get(base) || repo.refs.get(base);
        if (!headSha || !baseSha) {
          sendJson(res, 422, { message: 'Invalid head or base branch' }, {}, reqId);
          return;
        }

        const pullNum = ++repo.pullCounter;
        const now = new Date().toISOString();
        const pull: PullRequest = {
          number: pullNum,
          title,
          body: pullBody,
          state: 'open',
          head: { ref: head, sha: headSha },
          base: { ref: base, sha: baseSha },
          merged: false,
          mergeable: true,
          created_at: now,
          updated_at: now,
          user: { login: viewer.login, id: viewer.id },
        };
        repo.pulls.set(pullNum, pull);
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

      const currentBaseSha = repo.branches.get(pull.base.ref) || pull.base.sha;
      const currentHeadSha = repo.branches.get(pull.head.ref) || pull.head.sha;

      const ancestorSha = store.findCommonAncestor(currentBaseSha, currentHeadSha) || pull.base.sha;
      const ancestorFiles = store.getFilesAtCommit(ancestorSha);
      const baseFiles = store.getFilesAtCommit(currentBaseSha);
      const headFiles = store.getFilesAtCommit(currentHeadSha);

      // Conflict detection: both base and head changed the same file differently
      let conflict = false;
      const allPaths = new Set([...ancestorFiles.keys(), ...baseFiles.keys(), ...headFiles.keys()]);
      for (const p of allPaths) {
        const aSha = ancestorFiles.get(p)?.sha;
        const bSha = baseFiles.get(p)?.sha;
        const hSha = headFiles.get(p)?.sha;
        if (bSha !== aSha && hSha !== aSha && bSha !== hSha) {
          conflict = true;
          break;
        }
      }

      if (conflict) {
        sendJson(res, 405, { message: 'Pull request cannot be merged due to conflict' }, {}, reqId);
        return;
      }

      // Merge files: apply head changes onto base files
      const mergedFiles = new Map<string, { sha: string; mode: string }>(baseFiles);
      for (const [p, hEntry] of headFiles) {
        mergedFiles.set(p, hEntry);
      }
      for (const [p] of ancestorFiles) {
        if (!headFiles.has(p) && baseFiles.get(p)?.sha === ancestorFiles.get(p)?.sha) {
          mergedFiles.delete(p);
        }
      }

      const newTreeSha = store.buildTreeFromFiles(mergedFiles);
      const commitTitle = body.commit_title || `Merge pull request #${pull.number} from ${pull.head.ref}`;
      const mergeCommit = store.saveCommit(
        newTreeSha,
        [currentBaseSha],
        commitTitle,
        { name: viewer.name, email: viewer.email, date: new Date().toISOString() },
        { name: viewer.name, email: viewer.email, date: new Date().toISOString() },
      );

      // Advance base branch
      repo.branches.set(pull.base.ref, mergeCommit.sha);
      repo.refs.set(`refs/heads/${pull.base.ref}`, mergeCommit.sha);

      // Update pull request
      pull.state = 'closed';
      pull.merged = true;
      pull.merged_at = new Date().toISOString();
      pull.merge_commit_sha = mergeCommit.sha;
      pull.updated_at = pull.merged_at;

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
