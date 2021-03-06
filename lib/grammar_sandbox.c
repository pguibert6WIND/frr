/*
 * Testing shim and API examples for the new CLI backend.
 *
 * This unit defines a number of commands in the old engine that can
 * be used to test and interact with the new engine.
 *
 * This shim should be removed upon integration. It is currently hooked in
 * vtysh/vtysh.c. It has no header, vtysh.c merely includes this entire unit
 * since it clutters up the makefiles less and this is only a temporary shim.
 *
 * --
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "command.h"
#include "memory_vty.h"
#include "graph.h"
#include "command_match.h"

#define GRAMMAR_STR "CLI grammar sandbox\n"

DEFINE_MTYPE_STATIC(LIB, CMD_TOKENS, "Command desc")

#define MAXDEPTH 64

/** headers **/
void
grammar_sandbox_init (void);
void
pretty_print_graph (struct vty *vty, struct graph_node *, int, int, struct graph_node **, size_t);
void
init_cmdgraph (struct vty *, struct graph **);
vector
completions_to_vec (struct list *);
int
compare_completions (const void *, const void *);

/** shim interface commands **/
struct graph *nodegraph;

DEFUN (grammar_test,
       grammar_test_cmd,
       "grammar parse LINE...",
       GRAMMAR_STR
       "parse a command\n"
       "command to pass to new parser\n")
{
  int idx_command = 2;
  // make a string from tokenized command line
  char *command = argv_concat (argv, argc, idx_command);

  // create cmd_element for parser
  struct cmd_element *cmd = XCALLOC (MTYPE_CMD_TOKENS, sizeof (struct cmd_element));
  cmd->string = command;
  cmd->doc = "0\n1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n";
  cmd->func = NULL;

  // parse the command and install it into the command graph
  command_parse_format (nodegraph, cmd);

  return CMD_SUCCESS;
}

DEFUN (grammar_test_complete,
       grammar_test_complete_cmd,
       "grammar complete COMMAND...",
       GRAMMAR_STR
       "attempt to complete input on DFA\n"
       "command to complete\n")
{
  int idx_command = 2;
  char *cmdstr = argv_concat (argv, argc, idx_command);
  if (!cmdstr)
    return CMD_SUCCESS;

  vector command = cmd_make_strvec (cmdstr);

  // generate completions of user input
  struct list *completions;
  enum matcher_rv result = command_complete (nodegraph, command, &completions);

  // print completions or relevant error message
  if (!MATCHER_ERROR(result))
    {
      vector comps = completions_to_vec (completions);
      struct cmd_token *tkn;

      // calculate length of longest tkn->text in completions
      unsigned int width = 0, i = 0;
      for (i = 0; i < vector_active (comps); i++) {
        tkn = vector_slot (comps, i);
        unsigned int len = strlen (tkn->text);
        width = len > width ? len : width;
      }

      // print completions
      for (i = 0; i < vector_active (comps); i++) {
        tkn = vector_slot (comps, i);
        vty_out (vty, "  %-*s  %s%s", width, tkn->text, tkn->desc, VTY_NEWLINE);
      }

      for (i = 0; i < vector_active (comps); i++)
        del_cmd_token ((struct cmd_token *) vector_slot (comps, i));
      vector_free (comps);
    }
  else
    vty_out (vty, "%% No match%s", VTY_NEWLINE);

  // free resources
  list_delete (completions);
  cmd_free_strvec (command);
  free (cmdstr);

  return CMD_SUCCESS;
}

DEFUN (grammar_test_match,
       grammar_test_match_cmd,
       "grammar match COMMAND...",
       GRAMMAR_STR
       "attempt to match input on DFA\n"
       "command to match\n")
{
  int idx_command = 2;
  if (argv[2]->arg[0] == '#')
    return CMD_SUCCESS;

  char *cmdstr = argv_concat(argv, argc, idx_command);
  vector command = cmd_make_strvec (cmdstr);

  struct list *argvv = NULL;
  const struct cmd_element *element = NULL;
  enum matcher_rv result = command_match (nodegraph, command, &argvv, &element);

  // print completions or relevant error message
  if (element)
    {
      vty_out (vty, "Matched: %s%s", element->string, VTY_NEWLINE);
      struct listnode *ln;
      struct cmd_token *token;
      for (ALL_LIST_ELEMENTS_RO(argvv,ln,token))
        vty_out (vty, "%s -- %s%s", token->text, token->arg, VTY_NEWLINE);

      vty_out (vty, "func: %p%s", element->func, VTY_NEWLINE);

      list_delete (argvv);
    }
  else {
     assert(MATCHER_ERROR(result));
     switch (result) {
       case MATCHER_NO_MATCH:
          vty_out (vty, "%% Unknown command%s", VTY_NEWLINE);
          break;
       case MATCHER_INCOMPLETE:
          vty_out (vty, "%% Incomplete command%s", VTY_NEWLINE);
          break;
       case MATCHER_AMBIGUOUS:
          vty_out (vty, "%% Ambiguous command%s", VTY_NEWLINE);
          break;
       default:
          vty_out (vty, "%% Unknown error%s", VTY_NEWLINE);
          break;
     }
  }

  // free resources
  cmd_free_strvec (command);
  free (cmdstr);

  return CMD_SUCCESS;
}

/**
 * Testing shim to test docstrings
 */
DEFUN (grammar_test_doc,
       grammar_test_doc_cmd,
       "grammar test docstring",
       GRAMMAR_STR
       "Test function for docstring\n"
       "Command end\n")
{
  // create cmd_element with docstring
  struct cmd_element *cmd = XCALLOC (MTYPE_CMD_TOKENS, sizeof (struct cmd_element));
  cmd->string = XSTRDUP (MTYPE_CMD_TOKENS, "test docstring <example|selector follow> (1-255) end VARIABLE [OPTION|set lol] . VARARG");
  cmd->doc = XSTRDUP (MTYPE_CMD_TOKENS,
             "Test stuff\n"
             "docstring thing\n"
             "first example\n"
             "second example\n"
             "follow\n"
             "random range\n"
             "end thingy\n"
             "variable\n"
             "optional variable\n"
             "optional set\n"
             "optional lol\n"
             "vararg!\n");
  cmd->func = NULL;

  // parse element
  command_parse_format (nodegraph, cmd);

  return CMD_SUCCESS;
}

/**
 * Debugging command to print command graph
 */
DEFUN (grammar_test_show,
       grammar_test_show_cmd,
       "grammar show [doc]",
       GRAMMAR_STR
       "print current accumulated DFA\n"
       "include docstrings\n")
{
  struct graph_node *stack[MAXDEPTH];

  if (!nodegraph)
    vty_out(vty, "nodegraph uninitialized\r\n");
  else
    pretty_print_graph (vty, vector_slot (nodegraph->nodes, 0), 0, argc >= 3, stack, 0);
  return CMD_SUCCESS;
}

DEFUN (grammar_init_graph,
       grammar_init_graph_cmd,
       "grammar init",
       GRAMMAR_STR
       "(re)initialize graph\n")
{
  graph_delete_graph (nodegraph);
  init_cmdgraph (vty, &nodegraph);
  return CMD_SUCCESS;
}

/* this is called in vtysh.c to set up the testing shim */
void grammar_sandbox_init(void) {
  init_cmdgraph (NULL, &nodegraph);

  // install all enable elements
  install_element (ENABLE_NODE, &grammar_test_cmd);
  install_element (ENABLE_NODE, &grammar_test_show_cmd);
  install_element (ENABLE_NODE, &grammar_test_match_cmd);
  install_element (ENABLE_NODE, &grammar_test_complete_cmd);
  install_element (ENABLE_NODE, &grammar_test_doc_cmd);
  install_element (ENABLE_NODE, &grammar_init_graph_cmd);
}

#define item(x) { x, #x }
struct message tokennames[] = {
  item(WORD_TKN),         // words
  item(VARIABLE_TKN),     // almost anything
  item(RANGE_TKN),        // integer range
  item(IPV4_TKN),         // IPV4 addresses
  item(IPV4_PREFIX_TKN),  // IPV4 network prefixes
  item(IPV6_TKN),         // IPV6 prefixes
  item(IPV6_PREFIX_TKN),  // IPV6 network prefixes

  /* plumbing types */
  item(SELECTOR_TKN),     // marks beginning of selector
  item(OPTION_TKN),       // marks beginning of option
  item(NUL_TKN),          // dummy token
  item(START_TKN),        // first token in line
  item(END_TKN),          // last token in line
  { 0, NULL }
};
size_t tokennames_max = array_size(tokennames);

/**
 * Pretty-prints a graph, assuming it is a tree.
 *
 * @param start the node to take as the root
 * @param level indent level for recursive calls, always pass 0
 */
void
pretty_print_graph (struct vty *vty, struct graph_node *start, int level,
		int desc, struct graph_node **stack, size_t stackpos)
{
  // print this node
  char tokennum[32];
  struct cmd_token *tok = start->data;

  snprintf(tokennum, sizeof(tokennum), "%d?", tok->type);
  vty_out(vty, "%s", LOOKUP_DEF(tokennames, tok->type, tokennum));
  if (tok->text)
    vty_out(vty, ":\"%s\"", tok->text);
  if (desc)
    vty_out(vty, " ?'%s'", tok->desc);
  vty_out(vty, " ");

  if (stackpos == MAXDEPTH)
    {
      vty_out(vty, " -aborting! (depth limit)%s", VTY_NEWLINE);
      return;
    }
  stack[stackpos++] = start;

  int numto = desc ? 2 : vector_active (start->to);
  if (numto)
    {
      if (numto > 1)
        vty_out(vty, "%s", VTY_NEWLINE);
      for (unsigned int i = 0; i < vector_active (start->to); i++)
        {
          struct graph_node *adj = vector_slot (start->to, i);
          // if we're listing multiple children, indent!
          if (numto > 1)
            for (int j = 0; j < level+1; j++)
              vty_out(vty, "    ");
          // if this node is a vararg, just print *
          if (adj == start)
            vty_out(vty, "*");
          else if (((struct cmd_token *)adj->data)->type == END_TKN)
            vty_out(vty, "--END%s", VTY_NEWLINE);
          else {
            size_t k;
            for (k = 0; k < stackpos; k++)
              if (stack[k] == adj) {
                vty_out(vty, "<<loop@%zu %s", k, VTY_NEWLINE);
                break;
              }
            if (k == stackpos)
              pretty_print_graph (vty, adj, numto > 1 ? level+1 : level, desc, stack, stackpos);
          }
       }
    }
  else
    vty_out(vty, "%s", VTY_NEWLINE);
}

/** stuff that should go in command.c + command.h */
void
init_cmdgraph (struct vty *vty, struct graph **graph)
{
  // initialize graph, add start noe
  *graph = graph_new ();
  struct cmd_token *token = new_cmd_token (START_TKN, 0, NULL, NULL);
  graph_new_node (*graph, token, (void (*)(void *)) &del_cmd_token);
  if (vty)
    vty_out (vty, "initialized graph%s", VTY_NEWLINE);
}

int
compare_completions (const void *fst, const void *snd)
{
  struct cmd_token *first = *(struct cmd_token **) fst,
                     *secnd = *(struct cmd_token **) snd;
  return strcmp (first->text, secnd->text);
}

vector
completions_to_vec (struct list *completions)
{
  vector comps = vector_init (VECTOR_MIN_SIZE);

  struct listnode *ln;
  struct cmd_token *token;
  unsigned int i, exists;
  for (ALL_LIST_ELEMENTS_RO(completions,ln,token))
  {
    // linear search for token in completions vector
    exists = 0;
    for (i = 0; i < vector_active (comps) && !exists; i++)
    {
      struct cmd_token *curr = vector_slot (comps, i);
      exists = !strcmp (curr->text, token->text) &&
               !strcmp (curr->desc, token->desc);
    }

    if (!exists)
      vector_set (comps, copy_cmd_token (token));
  }

  // sort completions
  qsort (comps->index,
         vector_active (comps),
         sizeof (void *),
         &compare_completions);

  return comps;
}

static void vty_do_exit(void)
{
  printf ("\nend.\n");
  exit (0);
}

struct thread_master *master;

int main(int argc, char **argv)
{
  struct thread thread;

  master = thread_master_create ();

  zlog_default = openzlog ("grammar_sandbox", ZLOG_NONE, 0,
                           LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);
  zlog_set_level (NULL, ZLOG_DEST_SYSLOG, ZLOG_DISABLED);
  zlog_set_level (NULL, ZLOG_DEST_STDOUT, LOG_DEBUG);
  zlog_set_level (NULL, ZLOG_DEST_MONITOR, ZLOG_DISABLED);

  /* Library inits. */
  cmd_init (1);
  host.name = strdup ("test");

  vty_init (master);
  memory_init ();
  grammar_sandbox_init();

  vty_stdio (vty_do_exit);

  /* Fetch next active thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  exit (0);
}
