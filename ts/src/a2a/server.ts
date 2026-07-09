/**
 * Real A2A server round trip using the official @a2a-js/sdk server stack:
 * an AgentExecutor publishes a completed Task (with a co-signed artifact) to the
 * ExecutionEventBus; DefaultRequestHandler.sendMessage() drives the InMemoryTaskStore
 * + event bus and returns the final Task. The "consumer" then reads task.artifacts.
 *
 * This is the genuine A2A request-handler / task-store / event-bus path. We call the
 * request handler directly rather than over an HTTP transport (the transport is
 * secondary; the middleware + receipt + verify round-trip is the deliverable).
 */
import { randomUUID } from 'node:crypto';
import {
  DefaultRequestHandler,
  InMemoryTaskStore,
  type AgentExecutor,
  type RequestContext,
  type ExecutionEventBus,
} from '@a2a-js/sdk/server';
import type { AgentCard, Message, Task, Artifact } from '@a2a-js/sdk';
import { TestSigner, generateTestSigner } from '../mcp/vitni-middleware.js';
import { vitniArtifact, A2APartLike } from './vitni-a2a-middleware.js';

export interface A2ARoundTripOptions {
  signer?: TestSigner;
  skill: string;
  text: string;
}

export interface A2ARoundTripResult {
  /** The co-signed artifact the consumer received (with metadata receipt). */
  artifact: Artifact;
  /** The full completed Task. */
  task: Task;
  signer: TestSigner;
}

/** A minimal agent card for the demo agent. */
function buildAgentCard(skill: string): AgentCard {
  return {
    protocolVersion: '0.3.0',
    name: 'vitni-a2a-demo',
    description: 'A2A agent that emits Vitni receipts on its artifacts.',
    url: 'http://localhost/a2a',
    version: '0.1.0',
    capabilities: { streaming: false },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills: [
      {
        id: skill,
        name: skill,
        description: `${skill} skill (co-signed)`,
        tags: ['demo'],
      },
    ],
  } as AgentCard;
}

/**
 * Build an AgentExecutor that produces a text artifact and co-signs it.
 * The artifact's parts mirror the request text; the middleware attaches the receipt.
 */
function buildExecutor(signer: TestSigner, skill: string): AgentExecutor {
  return {
    async execute(requestContext: RequestContext, eventBus: ExecutionEventBus): Promise<void> {
      const t0 = performance.now();
      const userMessage = requestContext.userMessage;

      // Extract the request's text parts (for inputs_hash). Map A2A parts to the
      // shape the §9 hasher understands.
      const requestParts: A2APartLike[] = (userMessage.parts ?? []).map(toHashPart);

      // The agent's "work": echo a summary as a text artifact.
      const summary = `summary: ${requestParts
        .filter((p) => p.kind === 'text')
        .map((p) => String(p.text))
        .join(' ')}`;

      const artifact: Artifact = {
        artifactId: randomUUID(),
        name: 'result',
        parts: [{ kind: 'text', text: summary }],
      };

      const wallMs = String(Math.max(0, Math.round(performance.now() - t0)));

      // Co-signing middleware: build + sign the receipt, attach at artifact.metadata.
      vitniArtifact(artifact as unknown as Parameters<typeof vitniArtifact>[0], {
        signer,
        skill,
        requestParts,
        wallMs,
      });

      // Publish the completed Task carrying the co-signed artifact.
      const task: Task = {
        kind: 'task',
        id: requestContext.taskId,
        contextId: requestContext.contextId,
        status: { state: 'completed' },
        artifacts: [artifact],
      };
      eventBus.publish(task);
      eventBus.finished();
    },
    async cancelTask(): Promise<void> {
      // no-op for the demo
    },
  };
}

/** Map an A2A SDK Part to the §9 hasher's part shape. */
function toHashPart(part: unknown): A2APartLike {
  const p = part as { kind: string; text?: unknown; data?: unknown; file?: unknown };
  if (p.kind === 'text') return { kind: 'text', text: p.text };
  if (p.kind === 'data') return { kind: 'data', data: p.data };
  if (p.kind === 'file') return { kind: 'file', file: p.file as A2APartLike['file'] };
  return { kind: p.kind };
}

/**
 * Run a full A2A round trip and return the co-signed artifact the consumer received.
 */
export async function runA2ARoundTrip(opts: A2ARoundTripOptions): Promise<A2ARoundTripResult> {
  const signer = opts.signer ?? generateTestSigner();
  const agentCard = buildAgentCard(opts.skill);
  const taskStore = new InMemoryTaskStore();
  const executor = buildExecutor(signer, opts.skill);
  const handler = new DefaultRequestHandler(agentCard, taskStore, executor);

  const userMessage: Message = {
    kind: 'message',
    messageId: randomUUID(),
    role: 'user',
    parts: [{ kind: 'text', text: opts.text }],
  };

  // The consumer sends a message and receives the final Task.
  const result = await handler.sendMessage({ message: userMessage });

  if (!isTask(result)) {
    throw new Error('expected a Task result from the A2A handler');
  }
  const artifact = result.artifacts?.[0];
  if (!artifact) {
    throw new Error('A2A task returned no artifact');
  }

  return { artifact, task: result, signer };
}

function isTask(v: Message | Task): v is Task {
  return (v as Task).kind === 'task';
}
