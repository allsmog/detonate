"use client";

import { useParams } from "next/navigation";

import { SubmissionDetail } from "@/components/submission-detail";

export default function SubmissionPage() {
  const params = useParams();
  const id = params.id as string;

  return (
    <div className="py-8 px-4">
      <SubmissionDetail id={id} />
    </div>
  );
}
